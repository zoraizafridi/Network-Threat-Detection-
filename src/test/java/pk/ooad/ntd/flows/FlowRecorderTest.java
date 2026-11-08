package pk.ooad.ntd.flows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FlowRecorderTest {

    private static final Instant T0 = Instant.parse("2026-11-05T12:00:00Z");
    private static final List<FlowRecorder.LabelRule> RULES = List.of(
            new FlowRecorder.LabelRule("PORT_SCAN", Pattern.compile(".*PORT_SCAN.*")),
            new FlowRecorder.LabelRule("BRUTE_FORCE", Pattern.compile(".*AUTH_FAILED.*")),
            new FlowRecorder.LabelRule("DATA_EXFIL", Pattern.compile(".*EXFILTRATION.*")),
            new FlowRecorder.LabelRule("DOS_FLOOD", Pattern.compile(".*DOS_FLOOD.*")),
            new FlowRecorder.LabelRule("NORMAL", Pattern.compile(".*NORMAL.*"))
    );

    private static FlowRecorder recorder(int idleSeconds, int maxRecords, int retentionMinutes) {
        return new FlowRecorder(true, idleSeconds, maxRecords, 5_000, retentionMinutes, Set.of(53, 123), RULES);
    }

    private static NetworkEvent event(long id, Instant at, String src, String dst, int port, long bytes,
                                      boolean success, String payload) {
        return new NetworkEvent(id, at, src, dst, port, bytes, EventType.REQUEST, success, payload, false);
    }

    @Test
    @DisplayName("Events on the same five-tuple fold into one flow with summed counters")
    void aggregatesByFiveTuple() {
        FlowRecorder recorder = recorder(30, 100, 30);
        recorder.accept(event(1, T0, "10.0.0.5", "10.0.0.9", 443, 100L, true, "NORMAL_PAYLOAD"));
        recorder.accept(event(2, T0.plusSeconds(2), "10.0.0.5", "10.0.0.9", 443, 250L, true, "NORMAL_PAYLOAD"));
        recorder.accept(event(3, T0.plusSeconds(4), "10.0.0.5", "10.0.0.9", 443, 50L, false, "NORMAL_PAYLOAD"));

        List<FlowRecord> rows = recorder.query(FlowQuery.all(10));

        assertEquals(1, rows.size(), "one tuple must produce exactly one flow");
        FlowRecord flow = rows.get(0);
        assertEquals(400L, flow.bytesOut());
        assertEquals(3L, flow.packets());
        assertEquals(0L, flow.bytesIn(), "the simulated feed never reports reply bytes");
        assertEquals(T0, flow.startTime());
        assertEquals(T0.plusSeconds(4), flow.endTime());
        assertEquals(4_000L, flow.durationMs());
        assertEquals("TCP", flow.protocol());
        assertEquals(List.of("OK", "FAILED"), flow.flags());
        assertEquals("NORMAL", flow.label());
        assertFalse(flow.ended(), "a flow inside the idle window is still open");
        assertEquals(1, recorder.activeCount());
        assertEquals(0, recorder.closedCount());
    }

    @Test
    @DisplayName("A gap longer than the idle timeout closes the flow and opens a new one")
    void idleTimeoutSplitsFlows() {
        FlowRecorder recorder = recorder(30, 100, 30);
        recorder.accept(event(1, T0, "10.0.0.5", "10.0.0.9", 443, 100L, true, "NORMAL_PAYLOAD"));
        recorder.accept(event(2, T0.plusSeconds(31), "10.0.0.5", "10.0.0.9", 443, 200L, true, "NORMAL_PAYLOAD"));

        List<FlowRecord> rows = recorder.query(FlowQuery.all(10));

        assertEquals(2, rows.size(), "the idle gap must split the tuple into two flows");
        FlowRecord newest = rows.get(0);
        FlowRecord oldest = rows.get(1);
        assertEquals(T0.plusSeconds(31), newest.startTime());
        assertFalse(newest.ended());
        assertEquals(1L, newest.packets());
        assertEquals(T0, oldest.startTime());
        assertTrue(oldest.ended());
        assertEquals(1L, oldest.packets());
        assertEquals(1, recorder.activeCount());
        assertEquals(1, recorder.closedCount());
    }

    @Test
    @DisplayName("Querying a quiet feed closes idle flows exactly once")
    void queryExpiresIdleFlows() {
        FlowRecorder recorder = recorder(30, 100, 30);
        recorder.accept(event(1, T0, "10.0.0.5", "10.0.0.9", 443, 10L, true, "NORMAL_PAYLOAD"));
        recorder.accept(event(2, T0.plusSeconds(120), "10.0.0.6", "10.0.0.9", 443, 10L, true, "NORMAL_PAYLOAD"));

        List<FlowRecord> first = recorder.query(FlowQuery.all(10));
        List<FlowRecord> second = recorder.query(FlowQuery.all(10));

        assertEquals(2, first.size());
        assertEquals(2, second.size(), "expiry must not duplicate or drop flows");
        assertEquals(1, recorder.closedCount());
        assertEquals(1, recorder.activeCount());
    }

    @Test
    @DisplayName("The closed ring buffer keeps only the newest maxRecords entries")
    void evictsOldestClosedRecords() {
        FlowRecorder recorder = recorder(30, 2, 30);
        for (int index = 0; index < 5; index++) {
            Instant at = T0.plusSeconds(index * 60L);
            recorder.accept(event(index, at, "10.0.0." + (10 + index), "10.0.0.9", 443, 10L, true, "NORMAL_PAYLOAD"));
        }

        List<FlowRecord> rows = recorder.query(FlowQuery.all(100));

        assertEquals(2, recorder.closedCount(), "the closed buffer is capped at flow.maxRecords");
        assertEquals(2, recorder.getMaxRecords());
        assertEquals(3, rows.size(), "two closed records plus the still-open flow");
    }

    @Test
    @DisplayName("Closed records older than the retention window are purged")
    void purgesBeyondRetention() {
        FlowRecorder recorder = recorder(30, 100, 1);
        recorder.accept(event(1, T0, "10.0.0.5", "10.0.0.9", 443, 10L, true, "NORMAL_PAYLOAD"));
        recorder.accept(event(2, T0.plusSeconds(300), "10.0.0.6", "10.0.0.9", 443, 10L, true, "NORMAL_PAYLOAD"));

        List<FlowRecord> rows = recorder.query(FlowQuery.all(100));

        assertEquals(1, rows.size(), "the flow older than flow.retentionMinutes must be gone");
        assertEquals("10.0.0.6", rows.get(0).srcIp());
        assertEquals(0, recorder.closedCount());
    }

    @Test
    @DisplayName("Query filters match source, destination, port and time window")
    void appliesQueryFilters() {
        FlowRecorder recorder = recorder(30, 100, 30);
        recorder.accept(event(1, T0, "10.0.0.5", "10.0.0.9", 443, 10L, true, "NORMAL_PAYLOAD"));
        recorder.accept(event(2, T0.plusSeconds(60), "10.0.0.6", "10.0.0.9", 53, 10L, true, "NORMAL_PAYLOAD"));
        recorder.accept(event(3, T0.plusSeconds(120), "10.0.0.5", "10.0.0.7", 8080, 10L, true, "NORMAL_PAYLOAD"));

        assertEquals(2, recorder.query(new FlowQuery("10.0.0.5", null, null, null, null, 10, true)).size());
        assertEquals(2, recorder.query(new FlowQuery(null, "10.0.0.9", null, null, null, 10, true)).size());
        assertEquals(1, recorder.query(new FlowQuery(null, null, 53, null, null, 10, true)).size());
        assertEquals(1, recorder.query(new FlowQuery(null, null, 8080, null, null, 10, true)).size());
        assertEquals(1, recorder.query(new FlowQuery(null, null, null, T0.plusSeconds(90), null, 10, true)).size());
        assertEquals(2, recorder.query(new FlowQuery(null, null, null, null, T0.plusSeconds(60), 10, true)).size());
        assertEquals(2, recorder.query(FlowQuery.all(2)).size(), "limit must cap the result");
        assertEquals(2, recorder.query(new FlowQuery(null, null, null, null, null, 10, false)).size(),
                "a closed-only query must skip the flow that is still open");
    }

    @Test
    @DisplayName("Labels come from the payload rules with the event type as a weaker fallback")
    void derivesLabels() {
        FlowRecorder recorder = recorder(30, 100, 30);
        recorder.accept(event(1, T0, "10.0.0.5", "10.0.0.9", 80, 10L, false, "PORT_SCAN_SYN"));
        recorder.accept(event(2, T0.plusSeconds(1), "10.0.0.6", "10.0.0.9", 22, 10L, false, "AUTH_FAILED user=root"));
        recorder.accept(event(3, T0.plusSeconds(2), "10.0.0.7", "10.0.0.9", 443, 10L, true, "DATA_EXFILTRATION_CHUNK"));
        recorder.accept(event(4, T0.plusSeconds(3), "10.0.0.8", "10.0.0.9", 80, 10L, true, "DOS_FLOOD_PAYLOAD"));
        recorder.accept(new NetworkEvent(5L, T0.plusSeconds(4), "10.0.0.9", "10.0.0.9", 80, 10L,
                EventType.LOGIN_ATTEMPT, true, null, false));

        List<String> labels = new ArrayList<>();
        for (FlowRecord flow : recorder.query(FlowQuery.all(100))) {
            labels.add(flow.label());
        }

        assertTrue(labels.contains("PORT_SCAN"));
        assertTrue(labels.contains("BRUTE_FORCE"));
        assertTrue(labels.contains("DATA_EXFIL"));
        assertTrue(labels.contains("DOS_FLOOD"));
        assertTrue(labels.contains("LOGIN_ATTEMPT"), "a payload-less event falls back to its event type");
    }

    @Test
    @DisplayName("A rule match outranks the event-type fallback on the same flow")
    void ruleOutranksFallback() {
        FlowRecorder recorder = recorder(30, 100, 30);
        recorder.accept(new NetworkEvent(1L, T0, "10.0.0.5", "10.0.0.9", 80, 10L,
                EventType.REQUEST, true, null, false));
        recorder.accept(event(2, T0.plusSeconds(1), "10.0.0.5", "10.0.0.9", 80, 10L, true, "NORMAL_PAYLOAD"));

        FlowRecord flow = recorder.query(FlowQuery.all(10)).get(0);

        assertEquals("NORMAL", flow.label());
        assertEquals(2L, flow.packets(), "both events must stay in the same flow");
    }

    @Test
    @DisplayName("UDP ports are classified from configuration and everything else is TCP")
    void classifiesProtocol() {
        FlowRecorder recorder = recorder(30, 100, 30);
        recorder.accept(event(1, T0, "10.0.0.5", "10.0.0.9", 53, 10L, true, "NORMAL_PAYLOAD"));
        recorder.accept(event(2, T0.plusSeconds(1), "10.0.0.5", "10.0.0.9", 123, 10L, true, "NORMAL_PAYLOAD"));
        recorder.accept(event(3, T0.plusSeconds(2), "10.0.0.5", "10.0.0.9", 443, 10L, true, "NORMAL_PAYLOAD"));

        List<String> protocols = new ArrayList<>();
        for (FlowRecord flow : recorder.query(FlowQuery.all(10))) {
            protocols.add(flow.protocol());
        }

        assertEquals(2, protocols.stream().filter("UDP"::equals).count());
        assertEquals(1, protocols.stream().filter("TCP"::equals).count());
    }

    @Test
    @DisplayName("Derived source ports are stable and distinct per destination port")
    void derivesStableSourcePorts() {
        int first = FlowRecorder.ephemeralPort("10.0.0.5", "10.0.0.9", 443);
        int again = FlowRecorder.ephemeralPort("10.0.0.5", "10.0.0.9", 443);
        int other = FlowRecorder.ephemeralPort("10.0.0.5", "10.0.0.9", 8080);

        assertEquals(first, again);
        assertNotEquals(first, other);
        assertTrue(first >= 1024 && first <= 65_535, "source ports must stay in the ephemeral range: " + first);
    }

    @Test
    @DisplayName("A disabled recorder stores nothing")
    void disabledRecorderIgnoresEvents() {
        FlowRecorder recorder = new FlowRecorder(false, 30, 100, 100, 30, Set.of(), RULES);
        recorder.accept(event(1, T0, "10.0.0.5", "10.0.0.9", 443, 10L, true, "NORMAL_PAYLOAD"));

        assertFalse(recorder.isEnabled());
        assertEquals(0, recorder.query(FlowQuery.all(10)).size());
    }

    @Test
    @DisplayName("Concurrent writers produce one consistent flow and no lost events")
    void handlesConcurrentWriters() throws InterruptedException {
        FlowRecorder recorder = recorder(60, 100, 30);
        int threads = 4;
        int perThread = 250;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        try {
            for (int thread = 0; thread < threads; thread++) {
                int base = thread * perThread;
                pool.submit(() -> {
                    start.await();
                    for (int index = 0; index < perThread; index++) {
                        int id = base + index;
                        recorder.accept(event(id, T0.plusMillis(id * 10L), "10.0.0.5", "10.0.0.9", 443, 1L,
                                true, "NORMAL_PAYLOAD"));
                    }
                    return null;
                });
            }
            start.countDown();
        } finally {
            pool.shutdown();
        }
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS), "writers must finish");

        List<FlowRecord> rows = recorder.query(FlowQuery.all(10));
        assertEquals(1, rows.size());
        assertEquals((long) threads * perThread, rows.get(0).packets(), "no event may be lost");
        assertEquals((long) threads * perThread, rows.get(0).bytesOut());
    }

    @Test
    @DisplayName("reset clears both the active map and the closed ring")
    void resetClearsState() {
        FlowRecorder recorder = recorder(30, 100, 30);
        recorder.accept(event(1, T0, "10.0.0.5", "10.0.0.9", 443, 10L, true, "NORMAL_PAYLOAD"));
        recorder.query(FlowQuery.all(10));
        assertTrue(recorder.activeCount() > 0);

        recorder.reset();

        assertEquals(0, recorder.activeCount());
        assertEquals(0, recorder.closedCount());
        assertEquals(0, recorder.query(FlowQuery.all(10)).size());
    }
}
