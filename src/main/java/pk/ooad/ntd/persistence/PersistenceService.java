package pk.ooad.ntd.persistence;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.detection.AlertUpdateListener;
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

public final class PersistenceService implements AlertListener, AlertUpdateListener, AutoCloseable {

    public static final int MIN_RETENTION_MINUTES = 5;
    public static final int MAX_RETENTION_MINUTES = 525_600;

    private volatile PersistenceSettings settings;
    private final Database database;
    private final FlowRepository flows;
    private final AlertRepository alerts;
    private final Stores stores;
    private final WriteBehindQueue<FlowRecord> flowQueue;
    private final WriteBehindQueue<AlertRecord> alertQueue;
    private final ScheduledExecutorService sweeper;
    private final AtomicInteger lastSwept = new AtomicInteger();
    private final AtomicBoolean sweepFaultLogged = new AtomicBoolean();
    private final AtomicBoolean inlineFaultLogged = new AtomicBoolean();

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
                        "Durable store unavailable at " + wanted.databasePath() + "; continuing in memory (" + ex + ")");
            }
        }
        this.settings = opened == null ? wanted.withEnabled(false) : wanted;
        this.database = opened;
        int memoryRows = Math.max(256, wanted.queueCapacity());
        if (opened == null) {
            this.flows = new InMemoryFlowRepository(memoryRows);
            this.alerts = new InMemoryAlertRepository(memoryRows);
            this.stores = Stores.memory(memoryRows);
            this.flowQueue = null;
            this.alertQueue = null;
        } else {
            this.flows = new SqliteFlowRepository(opened);
            this.alerts = new SqliteAlertRepository(opened);
            this.stores = Stores.sqlite(opened);
            this.flowQueue = new WriteBehindQueue<>("flow", settings.queueCapacity(), settings.batchSize(),
                    settings.flushIntervalMillis(), flows::insertBatch);
            this.alertQueue = new WriteBehindQueue<>("alert", settings.queueCapacity(), settings.batchSize(),
                    settings.flushIntervalMillis(), alerts::insertBatch);
        }
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

    public int schemaVersion() {
        if (database == null) {
            return 0;
        }
        try {
            return database.schemaVersion();
        } catch (SQLException ex) {
            return -1;
        }
    }

    public PersistenceSettings settings() {
        return settings;
    }

    public int setRetentionMinutes(int minutes) {
        if (minutes < MIN_RETENTION_MINUTES || minutes > MAX_RETENTION_MINUTES) {
            throw new IllegalArgumentException("retention must be between "
                    + MIN_RETENTION_MINUTES + " and " + MAX_RETENTION_MINUTES + " minutes");
        }
        int previous = settings.retentionMinutes();
        settings = settings.withRetentionMinutes(minutes);
        EventLog.getInstance().log(LogLevel.INFO, "persistence",
                "retention changed from " + previous + " to " + minutes + " minutes");
        return previous;
    }

    public void recordFlow(FlowRecord record) {
        if (record == null) {
            return;
        }
        if (flowQueue != null) {
            flowQueue.offer(record);
        } else {
            writeThrough(flows, record);
        }
    }

    @Override
    public void onAlert(Alert alert) {
        if (alert == null) {
            return;
        }
        AlertRecord row = toRecord(alert);
        if (alertQueue != null) {
            alertQueue.offer(row);
        } else {
            writeThrough(alerts, row);
        }
    }

    @Override
    public void onAlertUpdate(Alert alert) {
        onAlert(alert);
    }

    public List<FlowRecord> storedFlows(int limit) {
        if (!isEnabled()) {
            throw disabled("flows");
        }
        try {
            return flows.recent(limit);
        } catch (SQLException ex) {
            throw new PersistenceException("Cannot read stored flows", ex);
        }
    }

    public List<AlertRecord> storedAlerts(int limit) {
        if (!isEnabled()) {
            throw disabled("alerts");
        }
        try {
            return alerts.recent(limit);
        } catch (SQLException ex) {
            throw new PersistenceException("Cannot read stored alerts", ex);
        }
    }

    private PersistenceException disabled(String what) {
        return new PersistenceException("The durable store is disabled; set persistence.enabled=true to read stored "
                + what, null);
    }

    public void recordIncident(IncidentRecord record) {
        writeThrough(stores.incidents, record);
    }

    public List<IncidentRecord> storedIncidents(int limit) {
        return read("incidents", stores.incidents, limit);
    }

    public void recordContainment(ContainmentRecord record) {
        writeThrough(stores.containment, record);
    }

    public List<ContainmentRecord> storedContainment(int limit) {
        return read("containment actions", stores.containment, limit);
    }

    public void recordAudit(AuditRecord record) {
        writeThrough(stores.audit, record);
    }

    public List<AuditRecord> storedAudit(int limit) {
        return read("audit entries", stores.audit, limit);
    }

    public void recordNotification(NotificationRecord record) {
        writeThrough(stores.notifications, record);
    }

    public List<NotificationRecord> storedNotifications(int limit) {
        return read("notifications", stores.notifications, limit);
    }

    public void recordManifest(ManifestRecord record) {
        writeThrough(stores.manifests, record);
    }

    public List<ManifestRecord> storedManifests(int limit) {
        return read("evidence manifests", stores.manifests, limit);
    }

    public void recordModelSummary(ModelSummaryRecord record) {
        writeThrough(stores.models, record);
    }

    public ModelSummaryRecord lastModelSummary() {
        List<ModelSummaryRecord> rows = storedModelSummaries(1);
        return rows.isEmpty() ? null : rows.get(0);
    }

    public List<ModelSummaryRecord> storedModelSummaries(int limit) {
        return read("the model summary", stores.models, limit);
    }

    public int importFlows(List<FlowRecord> records) {
        if (!isEnabled()) {
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

    public int importAlerts(List<AlertRecord> records) {
        if (!isEnabled()) {
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
        String error = worst(named(flowQueue), named(alertQueue));
        int flowRows = 0;
        int alertRows = 0;
        try {
            flowRows = flows.count();
            alertRows = alerts.count();
        } catch (SQLException ex) {
            error = worst(error, "Cannot count rows: " + ex);
        }
        if (flowQueue == null) {
            return new PersistenceStatus(false, settings.databasePath().toString(), flowRows, alertRows,
                    0, 0, 0, 0, null, error);
        }
        Instant lastFlush = latest(flowQueue.lastFlush(), alertQueue.lastFlush());
        return new PersistenceStatus(true, database.file().toString(), flowRows, alertRows,
                flowQueue.queued(), alertQueue.queued(),
                flowQueue.dropped() + alertQueue.dropped(),
                flowQueue.written() + alertQueue.written(),
                lastFlush == null ? null : lastFlush.toString(),
                error);
    }

    public int sweepNow() {
        if (database == null) {
            return 0;
        }
        Instant cutoff = Instant.now().minus(Duration.ofMinutes(settings.retentionMinutes()));
        int deleted = 0;
        try {
            deleted += flows.deleteBefore(cutoff);
            deleted += alerts.deleteBefore(cutoff);
            deleted += stores.incidents.deleteBefore(cutoff);
            deleted += stores.containment.deleteBefore(cutoff);
            deleted += stores.audit.deleteBefore(cutoff);
            deleted += stores.notifications.deleteBefore(cutoff);
            deleted += stores.manifests.deleteBefore(cutoff);
            deleted += stores.models.deleteBefore(cutoff);
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

    public boolean flush(long timeoutMillis) {
        if (flowQueue == null) {
            return true;
        }
        long half = Math.max(1, timeoutMillis / 2);
        boolean flowDrained = flowQueue.flush(half);
        boolean alertDrained = alertQueue.flush(half);
        return flowDrained && alertDrained;
    }

    @Override
    public void close() {
        sweeper.shutdownNow();
        if (flowQueue != null) {
            flowQueue.close();
        }
        if (alertQueue != null) {
            alertQueue.close();
        }
        if (database != null) {
            database.close();
        }
    }

    private void sweepQuietly() {
        try {
            sweepNow();
        } catch (RuntimeException ex) {
            if (sweepFaultLogged.compareAndSet(false, true)) {
                EventLog.getInstance().log(LogLevel.WARN, "persistence", "Retention sweep crashed (" + ex + ")");
            }
        }
    }

    private static AlertRecord toRecord(Alert alert) {
        return AlertRecord.from(alert);
    }

    private <T> void writeThrough(RecordStore<T> store, T row) {
        if (row == null) {
            return;
        }
        try {
            store.insertBatch(List.of(row));
        } catch (SQLException ex) {
            if (inlineFaultLogged.compareAndSet(false, true)) {
                EventLog.getInstance().log(LogLevel.WARN, "persistence",
                        "Could not write a row outside the queues (" + ex + ")");
            }
        }
    }

    private static <T> List<T> read(String what, RecordStore<T> store, int limit) {
        try {
            return store.recent(limit);
        } catch (SQLException ex) {
            throw new PersistenceException("Cannot read stored " + what, ex);
        }
    }

    private static String named(WriteBehindQueue<?> queue) {
        return queue == null ? null : queue.lastError();
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
