package pk.ooad.ntd.ml;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.detection.AlertGate;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.flows.FlowRecord;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MlTest {

    private static final Instant BASE = Instant.parse("2026-11-08T08:00:00Z");

    private static FlowRecord flowFrom(String src, int index, long bytesOut, long packets,
                                       long durationMs, Instant at) {
        return new FlowRecord("f" + index, src, "10.0.0.9", 40_000 + (index % 5), 443, "TCP",
                bytesOut, 0L, packets, at, at.plusMillis(durationMs), List.of("OK"), "REQUEST", true, true);
    }

    private static FlowRecord flow(int index, long bytesOut, long packets, long durationMs, Instant at) {
        return flowFrom("10.0.0.5", index, bytesOut, packets, durationMs, at);
    }

    private static List<FlowRecord> normalFlows(int count) {
        List<FlowRecord> flows = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            flows.add(flow(i, 1_000 + i, 3, 500, BASE.plusSeconds(i)));
        }
        return flows;
    }

    private static MlFlowScorer scorer(AlertBus bus, AlertGate gate, double threshold) {
        return new MlFlowScorer(bus, gate, true, 2, 20, 3_600, threshold, 500, 42L,
                Severity.LOW, 300, 100);
    }

    private static void waitUntilReady(MlFlowScorer scorer) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (!"ready".equals(scorer.status().modelState()) && System.currentTimeMillis() < deadline) {
            scorer.train();
            Thread.sleep(10);
        }
        assertEquals("ready", scorer.status().modelState(), "the model must finish training");
    }

    @Test
    @DisplayName("The feature vector is log-scaled in six positions")
    void featureVectorShape() {
        FlowFeatures features = FeatureVector.of(flow(1, 1_023, 7, 2_000, BASE));
        double[] values = features.values();
        assertEquals(FlowFeatures.SIZE, values.length);
        assertEquals(6, values.length);
        assertEquals(Math.log1p(1_023), values[0], 1e-12);
        assertEquals(0.0, values[1], 1e-12);
        assertEquals(Math.log1p(7), values[2], 1e-12);
        assertEquals(2.0, values[3], 1e-12);
        assertEquals(Math.log1p(40_001), values[4], 1e-12);
        assertEquals(443.0, values[5], 1e-12);
    }

    @Test
    @DisplayName("K-means is deterministic for a fixed seed and separates two groups")
    void kMeansIsDeterministic() {
        double[][] points = {
                {0.0, 0.0}, {0.1, 0.1}, {0.2, -0.1},
                {10.0, 10.0}, {10.1, 10.2}, {9.9, 10.1}
        };
        KMeans.Result first = KMeans.fit(points, 2, 50, 7L);
        KMeans.Result second = KMeans.fit(points, 2, 50, 7L);
        assertEquals(2, first.centroids().length);
        for (int i = 0; i < first.centroids().length; i++) {
            assertArrayEquals(first.centroids()[i], second.centroids()[i], 1e-12);
        }
    }

    @Test
    @DisplayName("A disabled scorer records nothing and reports itself disabled")
    void disabledScorerIsSilent() {
        AlertBus bus = new AlertBus();
        List<Alert> received = new CopyOnWriteArrayList<>();
        bus.subscribe(received::add);
        MlFlowScorer scorer = new MlFlowScorer(bus, AlertGate.ALLOW_ALL, false, 2, 20, 3_600,
                0.5, 500, 42L, Severity.LOW, 300, 100);
        try {
            normalFlows(30).forEach(scorer::onFlow);
            assertEquals(0, scorer.sampleCount());
            assertEquals("disabled", scorer.status().modelState());
            assertEquals(0.0, scorer.score(flow(99, 9_000_000, 9_000, 9_000, BASE)));
            assertFalse(scorer.train());
            assertTrue(received.isEmpty());
        } finally {
            scorer.close();
        }
    }

    @Test
    @DisplayName("A cold scorer counts samples, then trains and scores a clear outlier")
    void trainsThenScoresOutlier() throws Exception {
        AlertBus bus = new AlertBus();
        List<Alert> received = new CopyOnWriteArrayList<>();
        bus.subscribe(received::add);
        MlFlowScorer scorer = scorer(bus, AlertGate.ALLOW_ALL, 0.5);
        try {
            normalFlows(5).forEach(scorer::onFlow);
            assertEquals("cold", scorer.status().modelState(), "below minSamples there is no model");
            assertEquals(5, scorer.sampleCount());
            assertEquals(0.0, scorer.score(flow(99, 1_000, 3, 500, BASE)), 1e-12);

            normalFlows(40).forEach(scorer::onFlow);
            int samples = scorer.sampleCount();
            assertEquals(45, samples + scorer.status().excluded(),
                    "every flow either trains the model or is kept out because its pair alerted");
            assertTrue(samples >= 20, "the model still holds the samples it needs");
            waitUntilReady(scorer);
            MlFlowScorer.Status ready = scorer.status();
            assertTrue(ready.clusters() >= 1 && ready.clusters() <= 2);
            assertEquals(0.5, ready.threshold(), 1e-12);
            assertTrue(!ready.lastTrainedAt().isEmpty());

            FlowRecord outlier = flowFrom("10.0.0.77", 41, 50_000_000, 900_000, 900_000,
                    BASE.plusSeconds(100));
            assertTrue(scorer.score(outlier) >= 0.5, "an extreme flow must score above the threshold");

            received.clear();
            scorer.onFlow(outlier);
            assertEquals(1, received.size(), "the outlier raises exactly one alert");
            Alert alert = received.get(0);
            assertEquals(AttackType.DATA_TRANSFER, alert.getAttackType());
            assertEquals(Severity.LOW, alert.getSeverity());
            assertEquals(MlFlowScorer.DETECTOR_NAME, alert.getDetectorName());
            assertTrue(alert.getDescription().contains("threshold 0.500"));
            assertTrue(alert.isSimulated(), "the simulated flag is carried through");

            scorer.onFlow(flowFrom("10.0.0.77", 42, 40_000_000, 800_000, 900_000,
                    BASE.plusSeconds(101)));
            assertEquals(1, received.size(), "the per-source cooldown holds the second alert back");
            assertTrue(scorer.status().anomalies() >= 2);
            assertTrue(scorer.status().scored() >= 2);
        } finally {
            scorer.close();
        }
    }

    @Test
    @DisplayName("The quality gate can suppress the alert without hiding the anomaly")
    void gateSuppressesPublication() throws Exception {
        AlertBus bus = new AlertBus();
        List<Alert> received = new CopyOnWriteArrayList<>();
        bus.subscribe(received::add);
        MlFlowScorer scorer = scorer(bus, alert -> false, 0.5);
        try {
            normalFlows(40).forEach(scorer::onFlow);
            waitUntilReady(scorer);
            scorer.onFlow(flow(41, 50_000_000, 900_000, 900_000, BASE.plusSeconds(100)));
            assertTrue(received.isEmpty());
            assertEquals(0, scorer.status().alerts());
            assertTrue(scorer.status().anomalies() >= 1);
        } finally {
            scorer.close();
        }
    }

    @Test
    @DisplayName("reset drops the model as well as the samples")
    void resetDropsTheModel() throws Exception {
        MlFlowScorer scorer = scorer(new AlertBus(), AlertGate.ALLOW_ALL, 0.5);
        try {
            normalFlows(30).forEach(scorer::onFlow);
            waitUntilReady(scorer);
            scorer.reset();
            assertEquals("cold", scorer.status().modelState());
            assertEquals(0, scorer.sampleCount());
            assertEquals(0, scorer.status().scored());
            assertEquals(0, scorer.status().clusters());
        } finally {
            scorer.close();
        }
    }
}
