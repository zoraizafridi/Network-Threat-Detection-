package pk.ooad.ntd.persistence;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Keeps closed flows and raised alerts on disk.
 *
 * <p>The service sits between the live producers and SQLite: producers hand it
 * a record and get an immediate answer, while two write-behind queues batch the
 * rows onto a daemon worker. Nothing here is on the detection critical path, and
 * a store that refuses to open degrades to {@code disabled} with one error in the
 * event log rather than stopping the detector.</p>
 *
 * <p>An hourly-by-default sweeper deletes rows older than
 * {@code persistence.retentionMinutes}. It is the same cutoff the in-memory flow
 * ring uses in spirit, only measured in hours rather than minutes.</p>
 */
public final class PersistenceService implements AlertListener, AutoCloseable {

    private final PersistenceSettings settings;
    private final Database database;
    private final FlowRepository flows;
    private final AlertRepository alerts;
    private final WriteBehindQueue<FlowRecord> flowQueue;
    private final WriteBehindQueue<AlertRecord> alertQueue;
    private final ScheduledExecutorService sweeper;
    private final AtomicInteger lastSwept = new AtomicInteger();
    private final AtomicBoolean sweepFaultLogged = new AtomicBoolean();

    public PersistenceService() {
        this(PersistenceSettings.from(ConfigManager.getInstance()));
    }

    public PersistenceService(PersistenceSettings requested) {
        PersistenceSettings wanted = requested == null ? PersistenceSettings.disabled() : requested;
        Database opened = null;
        if (wanted.enabled()) {
            try {
                opened = new Database(wanted.databasePath());
            } catch (SQLException | RuntimeException ex) {
                EventLog.getInstance().log(LogLevel.ERROR, "persistence",
                        "Durable store unavailable at " + wanted.databasePath() + "; continuing without it (" + ex + ")");
            }
        }
        this.settings = opened == null ? wanted.withEnabled(false) : wanted;
        this.database = opened;
        if (opened == null) {
            this.flows = null;
            this.alerts = null;
            this.flowQueue = null;
            this.alertQueue = null;
            this.sweeper = null;
            return;
        }
        this.flows = new FlowRepository(opened);
        this.alerts = new AlertRepository(opened);
        this.flowQueue = new WriteBehindQueue<>("flow", settings.queueCapacity(), settings.batchSize(),
                settings.flushIntervalMillis(), flows::insertBatch);
        this.alertQueue = new WriteBehindQueue<>("alert", settings.queueCapacity(), settings.batchSize(),
                settings.flushIntervalMillis(), alerts::insertBatch);
        this.sweeper = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "persistence-sweeper");
            thread.setDaemon(true);
            return thread;
        });
        this.sweeper.scheduleWithFixedDelay(this::sweepQuietly,
                settings.sweepMinutes(), settings.sweepMinutes(), TimeUnit.MINUTES);
    }

    public boolean isEnabled() {
        return database != null;
    }

    public PersistenceSettings settings() {
        return settings;
    }

    /** Never blocks: the record is queued, or counted as dropped when full. */
    public void recordFlow(FlowRecord record) {
        if (flowQueue != null) {
            flowQueue.offer(record);
        }
    }

    @Override
    public void onAlert(Alert alert) {
        if (alertQueue != null && alert != null) {
            alertQueue.offer(toRecord(alert));
        }
    }

    /** Stored flows, newest first. */
    public List<FlowRecord> storedFlows(int limit) {
        if (flows == null) {
            throw new PersistenceException("The durable store is disabled", null);
        }
        try {
            return flows.recent(limit);
        } catch (SQLException ex) {
            throw new PersistenceException("Cannot read stored flows", ex);
        }
    }

    /** Stored alerts, newest first. */
    public List<AlertRecord> storedAlerts(int limit) {
        if (alerts == null) {
            throw new PersistenceException("The durable store is disabled", null);
        }
        try {
            return alerts.recent(limit);
        } catch (SQLException ex) {
            throw new PersistenceException("Cannot read stored alerts", ex);
        }
    }

    /**
     * Bulk insert for the offline importer. This one is synchronous on purpose:
     * an import is a batch job that reports how many rows it stored, not a live
     * producer that should be buffered.
     *
     * @return how many rows were written
     */
    public int importFlows(List<FlowRecord> records) {
        if (flows == null) {
            throw new PersistenceException(
                    "The durable store is disabled; set persistence.enabled=true to import flows", null);
        }
        if (records == null || records.isEmpty()) {
            return 0;
        }
        int batch = Math.max(1, settings.batchSize());
        int written = 0;
        try {
            for (int from = 0; from < records.size(); from += batch) {
                List<FlowRecord> slice = records.subList(from, Math.min(records.size(), from + batch));
                flows.insertBatch(slice);
                written += slice.size();
            }
        } catch (SQLException ex) {
            throw new PersistenceException("Cannot import flows", ex);
        }
        return written;
    }

    /** Bulk insert for imported alerts, used by the evidence importer. */
    public int importAlerts(List<AlertRecord> records) {
        if (alerts == null) {
            throw new PersistenceException(
                    "The durable store is disabled; set persistence.enabled=true to import alerts", null);
        }
        if (records == null || records.isEmpty()) {
            return 0;
        }
        try {
            alerts.insertBatch(records);
        } catch (SQLException ex) {
            throw new PersistenceException("Cannot import alerts", ex);
        }
        return records.size();
    }

    public PersistenceStatus status() {
        if (database == null) {
            return PersistenceStatus.off(settings.databasePath().toString());
        }
        String error = worst(flowQueue.lastError(), alertQueue.lastError());
        int flowRows = 0;
        int alertRows = 0;
        try {
            flowRows = flows.count();
            alertRows = alerts.count();
        } catch (SQLException ex) {
            error = worst(error, "Cannot count rows: " + ex);
        }
        Instant lastFlush = latest(flowQueue.lastFlush(), alertQueue.lastFlush());
        return new PersistenceStatus(true, database.file().toString(), flowRows, alertRows,
                flowQueue.queued(), alertQueue.queued(),
                flowQueue.dropped() + alertQueue.dropped(),
                flowQueue.written() + alertQueue.written(),
                lastFlush == null ? null : lastFlush.toString(),
                error);
    }

    /** Deletes rows past the retention cutoff and reports how many went. */
    public int sweepNow() {
        if (database == null) {
            return 0;
        }
        Instant cutoff = Instant.now().minus(Duration.ofMinutes(settings.retentionMinutes()));
        int deleted = 0;
        try {
            deleted += flows.deleteBefore(cutoff);
            deleted += alerts.deleteBefore(cutoff);
            lastSwept.set(deleted);
        } catch (SQLException ex) {
            if (sweepFaultLogged.compareAndSet(false, true)) {
                EventLog.getInstance().log(LogLevel.WARN, "persistence", "Retention sweep failed (" + ex + ")");
            }
        }
        return deleted;
    }

    public int lastSweptRows() {
        return lastSwept.get();
    }

    /** @return true when both queues drained inside the budget */
    public boolean flush(long timeoutMillis) {
        if (database == null) {
            return true;
        }
        long half = Math.max(1, timeoutMillis / 2);
        boolean flowDrained = flowQueue.flush(half);
        boolean alertDrained = alertQueue.flush(half);
        return flowDrained && alertDrained;
    }

    @Override
    public void close() {
        if (database == null) {
            return;
        }
        if (sweeper != null) {
            sweeper.shutdownNow();
        }
        flowQueue.close();
        alertQueue.close();
        database.close();
    }

    private void sweepQuietly() {
        try {
            sweepNow();
        } catch (RuntimeException ex) {
            // A throwing task would silently cancel the schedule, so the outer
            // catch matters even though sweepNow already guards SQL.
            if (sweepFaultLogged.compareAndSet(false, true)) {
                EventLog.getInstance().log(LogLevel.WARN, "persistence", "Retention sweep crashed (" + ex + ")");
            }
        }
    }

    private static AlertRecord toRecord(Alert alert) {
        return AlertRecord.from(alert);
    }

    private static Instant latest(Instant left, Instant right) {
        if (left == null) {
            return right;
        }
        if (right == null) {
            return left;
        }
        return left.isAfter(right) ? left : right;
    }

    private static String worst(String left, String right) {
        return left != null ? left : right;
    }
}
