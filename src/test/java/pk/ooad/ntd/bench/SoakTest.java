package pk.ooad.ntd.bench;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.detection.DetectionEngine;
import pk.ooad.ntd.detection.Detector;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;

import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SoakTest {

    @Test
    @DisplayName("A soak accounts for every event it offers and reports ordered latencies")
    void soakAccountsForEveryEvent() {
        DetectionEngine engine = new DetectionEngine(new LinkedBlockingQueue<>(), new AlertBus(), 0);
        engine.addDetector(alertsOnEverything());

        Soak.Report report = Soak.run(engine, () -> 0L, 1, 400.0, 100);

        assertTrue(report.offered() > 0, "the producer must offer traffic");
        assertEquals(report.offered(), report.processed() + report.dropped(),
                "every offered event is either processed or refused");
        assertEquals(report.offered(), report.samples(), "every dequeued event must be timed");
        assertEquals(0L, report.dropped(), "nothing is dropped when admission allows every event");
        assertEquals(report.processed(), report.detected(), "the detector alerts on every event");
        assertEquals(report.detected(), report.alerts(), "the gate allows every alert through");
        assertEquals(0L, report.storeRows());
        assertTrue(report.meanMicros() > 0);
        assertTrue(report.p50Micros() <= report.p95Micros());
        assertTrue(report.p95Micros() <= report.p99Micros());
        assertTrue(report.p99Micros() <= report.maxMicros());
        assertTrue(report.service().mean() > 0, "the time inside detection must be measured");
        assertTrue(report.service().isOrdered(), "service percentiles must not decrease");
        assertTrue(report.service().p50() <= report.maxMicros(),
                "the work itself cannot be slower than the worst end-to-end sample");
        assertTrue(report.eventsPerSecond() > 0);
        assertTrue(report.maxQueueDepth() >= 0);
    }

    @Test
    @DisplayName("The soak summary names the duration, the counts and the latency figures")
    void summaryIsReadable() {
        DetectionEngine engine = new DetectionEngine(new LinkedBlockingQueue<>(), new AlertBus(), 0);
        Soak.Report report = Soak.run(engine, () -> 0L, 1, 200.0, 100);

        String summary = report.summary();
        assertTrue(summary.startsWith("Soak report: 1 s requested"));
        assertTrue(summary.contains("processed"));
        assertTrue(summary.contains("p99"));
        assertTrue(summary.contains("service"));
        assertTrue(summary.contains("throughput"));
        assertTrue(summary.contains("queue"));
    }

    @Test
    @DisplayName("An empty distribution reports zeros instead of failing")
    void emptyDistributionIsZero() {
        Soak.Dur empty = Soak.Dur.from(new long[0]);
        assertEquals(Soak.Dur.ZERO, empty);
        assertEquals(0.0, empty.p99());
        assertTrue(empty.isOrdered());
        assertTrue(empty.line().contains("p50 0.00 us"));
    }

    @Test
    @DisplayName("A distribution is summarised from its sorted samples in microseconds")
    void distributionSummarisesSamples() {
        long[] sorted = {1_000L, 2_000L, 3_000L, 4_000L, 10_000L};
        Soak.Dur dur = Soak.Dur.from(sorted);

        assertEquals(4.0, dur.mean(), 0.001);
        assertEquals(3.0, dur.p50(), 0.001);
        assertEquals(10.0, dur.p95(), 0.001, "nearest rank puts the fifth of five samples at p95");
        assertEquals(10.0, dur.p99(), 0.001);
        assertEquals(10.0, dur.max(), 0.001);
        assertTrue(dur.isOrdered());
    }

    @Test
    @DisplayName("A refused event is counted as dropped, not as processed")
    void dropsAreCountedSeparately() {
        DetectionEngine engine = new DetectionEngine(new LinkedBlockingQueue<>(), new AlertBus(), 0);
        engine.setAdmission(event -> false);

        Soak.Report report = Soak.run(engine, () -> 0L, 1, 200.0, 100);

        assertTrue(report.offered() > 0);
        assertEquals(report.offered(), report.dropped(), "every event is refused by admission");
        assertEquals(0L, report.processed());
        assertEquals(report.offered(), report.samples());
        assertEquals(0L, report.detected());
    }

    private static Detector alertsOnEverything() {
        return new Detector("soak-test") {
            @Override
            public Optional<Alert> analyze(NetworkEvent event) {
                return Optional.of(alertFactory.create(Severity.LOW, AttackType.PORT_SCAN,
                        event.sourceIp(), event.destIp(), name, "soak row", event.timestamp()));
            }

            @Override
            public void reset() {
            }
        };
    }
}
