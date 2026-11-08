package pk.ooad.ntd.persistence;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AlertStatus;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.flows.FlowRecorder;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.util.EventLog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PersistenceTest {

    @TempDir
    Path temp;

    private PersistenceSettings enabledSettings() {
        return PersistenceSettings.disabled()
                .withEnabled(true)
                .withDatabasePath(temp.resolve("data/ntd.db"))
                .withRetentionMinutes(60)
                .withBatchSize(50);
    }

    private static FlowRecord flow(String id, Instant start, long bytes) {
        return new FlowRecord(id, "10.0.0.5", "10.0.0.9", 40_000, 443, "TCP", bytes, 0L, 3,
                start, start.plusSeconds(1), List.of("OK"), "REQUEST", false, true);
    }

    @Test
    @DisplayName("A disabled store reports itself off and refuses reads and imports")
    void disabledStoreReportsOff() {
        try (PersistenceService service = new PersistenceService(PersistenceSettings.disabled())) {
            assertFalse(service.isEnabled());
            PersistenceStatus status = service.status();
            assertFalse(status.enabled());
            assertEquals(0, status.flowRows());
            assertTrue(service.flush(50), "flushing an absent store is a no-op success");
            assertEquals(0, service.sweepNow());
            assertThrows(PersistenceException.class, () -> service.storedFlows(5));
            assertThrows(PersistenceException.class, () -> service.storedAlerts(5));
            assertThrows(PersistenceException.class, () -> service.importFlows(List.of()));
            assertThrows(PersistenceException.class, () -> service.importAlerts(List.of()));
        }
    }

    @Test
    @DisplayName("Flows and alerts survive a flush and come back newest first")
    void flowsAndAlertsRoundTrip() {
        Instant now = Instant.now();
        try (PersistenceService service = new PersistenceService(enabledSettings())) {
            assertTrue(service.isEnabled());
            service.recordFlow(flow("f1", now.minusSeconds(30), 1_234));
            service.recordFlow(flow("f2", now.minusSeconds(10), 4_321));
            Alert alert = new AlertFactory().create(Severity.HIGH, AttackType.DOS_FLOOD,
                    "10.0.0.5", "10.0.0.9", "SignatureDetector", "flood", now);
            service.onAlert(alert);

            assertTrue(service.flush(5_000), "both queues must drain inside the budget");

            List<FlowRecord> flows = service.storedFlows(10);
            assertEquals(2, flows.size());
            assertEquals("f2", flows.get(0).id(), "newest start time first");
            assertEquals("f1", flows.get(1).id());
            assertEquals(1_234, flows.get(1).bytesOut());
            assertEquals(List.of("OK"), flows.get(1).flags());

            List<AlertRecord> alerts = service.storedAlerts(10);
            assertEquals(1, alerts.size());
            assertEquals(alert.getId(), alerts.get(0).id());
            assertEquals("HIGH", alerts.get(0).severity());
            assertEquals("DOS_FLOOD", alerts.get(0).attackType());

            PersistenceStatus status = service.status();
            assertTrue(status.enabled());
            assertEquals(2, status.flowRows());
            assertEquals(1, status.alertRows());
            assertEquals(0, status.droppedRows());
            assertEquals(3, status.writtenRows());
            assertNotNull(status.lastFlushAt());
            assertTrue(status.databasePath().endsWith("ntd.db"));
        }
    }

    @Test
    @DisplayName("Retention sweep deletes only rows older than the cutoff")
    void sweepDeletesOnlyExpiredRows() {
        Instant twoDaysAgo = Instant.now().minusSeconds(2 * 24 * 3600);
        try (PersistenceService service = new PersistenceService(enabledSettings())) {
            assertEquals(2, service.importFlows(List.of(
                    flow("old", twoDaysAgo, 10),
                    flow("new", Instant.now(), 20))));

            assertEquals(1, service.sweepNow());
            assertEquals(1, service.lastSweptRows());

            List<FlowRecord> remaining = service.storedFlows(10);
            assertEquals(1, remaining.size());
            assertEquals("new", remaining.get(0).id());
        }
    }

    @Test
    @DisplayName("A full write-behind queue refuses the newest item and counts the loss")
    void fullQueueRefusesAndCounts() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        WriteBehindQueue<String> queue = new WriteBehindQueue<>("test", 2, 1, 10, batch -> {
            entered.countDown();
            release.await(5, TimeUnit.SECONDS);
        });
        try {
            assertTrue(queue.offer("a"));
            assertTrue(entered.await(5, TimeUnit.SECONDS), "the worker must be inside the sink");
            assertTrue(queue.offer("b"));
            assertTrue(queue.offer("c"));
            assertFalse(queue.offer("d"), "the queue is full");
            assertEquals(1, queue.dropped());
            assertEquals(2, queue.queued());
        } finally {
            release.countDown();
            queue.close();
        }
    }

    @Test
    @DisplayName("A throwing sink is counted, described, and survived")
    void throwingSinkIsSurvived() {
        WriteBehindQueue<String> queue = new WriteBehindQueue<>("broken", 8, 2, 10, batch -> {
            throw new IllegalStateException("disk gone");
        });
        try {
            assertTrue(queue.offer("a"));
            long deadline = System.currentTimeMillis() + 5_000;
            while (queue.dropped() == 0 && System.currentTimeMillis() < deadline) {
                Thread.onSpinWait();
            }
            assertEquals(1, queue.dropped());
            assertEquals(0, queue.written());
            assertNotNull(queue.lastError());
            assertTrue(queue.lastError().contains("disk gone"));
            assertTrue(queue.flush(100), "a failed batch still leaves the queue empty");
        } finally {
            queue.close();
        }
    }

    @Test
    @DisplayName("A version 1 file is migrated in place to version 2 and keeps its rows")
    void schemaVersionOneMigratesInPlace() throws Exception {
        Path file = temp.resolve("legacy/ntd.db");
        Files.createDirectories(file.getParent());
        Instant start = Instant.parse("2026-11-01T10:00:00Z");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + file.toAbsolutePath());
             Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE flows (id TEXT PRIMARY KEY, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
                        src_port INTEGER NOT NULL, dst_port INTEGER NOT NULL, protocol TEXT NOT NULL,
                        bytes_out INTEGER NOT NULL, bytes_in INTEGER NOT NULL, packets INTEGER NOT NULL,
                        start_ms INTEGER NOT NULL, end_ms INTEGER NOT NULL, flags TEXT NOT NULL,
                        label TEXT NOT NULL, simulated INTEGER NOT NULL, ended INTEGER NOT NULL)
                    """);
            statement.execute("""
                    CREATE TABLE alerts (id TEXT PRIMARY KEY, ts_ms INTEGER NOT NULL, severity TEXT NOT NULL,
                        attack_type TEXT NOT NULL, source_ip TEXT NOT NULL, target_ip TEXT NOT NULL,
                        detector TEXT NOT NULL, description TEXT NOT NULL, simulated INTEGER NOT NULL)
                    """);
            statement.execute("INSERT INTO flows VALUES ('legacy', '10.0.0.5', '10.0.0.9', 40000, 443,"
                    + " 'TCP', 99, 0, 2, " + start.toEpochMilli() + ", "
                    + start.plusSeconds(1).toEpochMilli() + ", 'OK', 'REQUEST', 0, 1)");
            statement.execute("PRAGMA user_version = 1");
        }

        try (PersistenceService service = new PersistenceService(
                enabledSettings().withDatabasePath(file))) {
            assertTrue(service.isEnabled(), "a version 1 file is upgraded, not refused");
            assertEquals(2, service.schemaVersion());

            List<FlowRecord> flows = service.storedFlows(5);
            assertEquals(1, flows.size(), "the rows written by the older build survive");
            assertEquals("legacy", flows.get(0).id());
            assertEquals(99, flows.get(0).bytesOut());
            assertTrue(service.storedIncidents(5).isEmpty(),
                    "the six version 2 tables exist after the upgrade");

            Alert alert = new AlertFactory().create(Severity.HIGH, AttackType.PORT_SCAN,
                    "10.0.0.5", "10.0.0.9", "SignatureDetector", "scan", start);
            alert.fold(start.plusSeconds(2));
            alert.moveTo(AlertStatus.ACKNOWLEDGED);
            service.onAlert(alert);
            assertTrue(service.flush(5_000));

            AlertRecord stored = service.storedAlerts(5).get(0);
            assertEquals(2, stored.occurrences(), "the fold columns are added by the upgrade");
            assertEquals("ACKNOWLEDGED", stored.status());
        }
    }

    @Test
    @DisplayName("A corrupt file leaves the store off after one logged error and no crash")
    void corruptDatabaseDegradesToMemory() throws IOException {
        Path file = temp.resolve("broken/ntd.db");
        Files.createDirectories(file.getParent());
        Files.writeString(file, "this is not a sqlite database");
        EventLog.getInstance().clear();

        try (PersistenceService service = new PersistenceService(
                enabledSettings().withDatabasePath(file))) {
            assertFalse(service.isEnabled(), "a file that will not open must not pretend to be a store");
            assertEquals(0, service.schemaVersion());
            assertThrows(PersistenceException.class, () -> service.storedFlows(5));
            service.recordFlow(flow("held", Instant.now(), 10));
            assertTrue(service.flush(50), "a closed store still answers the queue");
        }

        long reported = EventLog.getInstance().getEntries().stream()
                .filter(line -> line.contains("Durable store unavailable"))
                .count();
        assertEquals(1, reported, "the failure is reported once, not on every write");
    }

    @Test
    @DisplayName("Closed flows reach the store through the recorder listener")
    void recorderCloseListenerReachesStore() {
        try (PersistenceService service = new PersistenceService(enabledSettings())) {
            FlowRecorder recorder = new FlowRecorder();
            recorder.addCloseListener(service::recordFlow);
            Instant t0 = Instant.parse("2026-11-08T10:00:00Z");
            recorder.accept(new NetworkEvent(1, t0, "10.0.0.5", "10.0.0.9", 443, 500,
                    EventType.REQUEST, true, "GET"));
            recorder.accept(new NetworkEvent(2, t0.plusSeconds(5), "10.0.0.6", "10.0.0.9", 443, 400,
                    EventType.REQUEST, true, "GET"));

            assertEquals(2, recorder.closeAllOpen());
            assertTrue(service.flush(5_000));

            List<FlowRecord> stored = service.storedFlows(10);
            assertEquals(2, stored.size());
            assertTrue(stored.stream().allMatch(FlowRecord::ended));
        }
    }
}
