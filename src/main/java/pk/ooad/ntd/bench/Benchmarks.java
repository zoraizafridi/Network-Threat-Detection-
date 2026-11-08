package pk.ooad.ntd.bench;

import pk.ooad.ntd.detection.AlertQualityGate;
import pk.ooad.ntd.detection.Detector;
import pk.ooad.ntd.detection.DetectorFactory;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.flows.FlowRecorder;
import pk.ooad.ntd.ml.AnomalyModel;
import pk.ooad.ntd.ml.FeatureVector;
import pk.ooad.ntd.ml.FlowFeatures;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Repeatable cost measurements for the parts that run on every event.
 *
 * <p>These are not a load test. They answer one question before a change ships:
 * did the hot path get slower? Everything is seeded and sized by the caller so
 * two runs on one machine can be compared, and the numbers are printed with
 * their operation count so a reader can see what was actually measured. A
 * benchmark that reports a rate without saying what one operation is has
 * already lost the argument.</p>
 */
public final class Benchmarks {

    public record Result(String name, int operations, long elapsedNanos) {
        public double microsPerOperation() {
            return operations <= 0 ? 0.0 : elapsedNanos / 1000.0 / operations;
        }

        public double operationsPerSecond() {
            return elapsedNanos <= 0 ? 0.0 : operations * 1_000_000_000.0 / elapsedNanos;
        }

        public String line() {
            return String.format(Locale.ROOT, "%-28s %9d ops %12.2f us/op %14.0f ops/s",
                    name, operations, microsPerOperation(), operationsPerSecond());
        }
    }

    private Benchmarks() {
    }

    public static List<Result> run(int scale) {
        int size = Math.max(200, scale);
        List<Result> results = new ArrayList<>();
        results.add(flowRecorderAccept(size));
        results.add(detectorAnalyze(size));
        results.add(featureExtraction(size));
        results.add(anomalyTraining(size));
        results.add(qualityGate(size));
        return results;
    }

    public static String report(List<Result> results) {
        StringBuilder out = new StringBuilder("Benchmark report")
                .append(System.lineSeparator());
        out.append(String.format(Locale.ROOT, "%-28s %9s %12s %14s",
                "benchmark", "ops", "us/op", "ops/s")).append(System.lineSeparator());
        for (Result result : results) {
            out.append(result.line()).append(System.lineSeparator());
        }
        return out.toString();
    }

    private static Result flowRecorderAccept(int scale) {
        FlowRecorder recorder = new FlowRecorder();
        Instant base = Instant.parse("2026-01-01T00:00:00Z");
        long started = System.nanoTime();
        for (int i = 0; i < scale; i++) {
            recorder.accept(event(i, base));
        }
        return new Result("flow-recorder.accept", scale, System.nanoTime() - started);
    }

    private static Result detectorAnalyze(int scale) {
        List<Detector> detectors = new DetectorFactory().createAll();
        Instant base = Instant.parse("2026-01-01T00:00:00Z");
        long started = System.nanoTime();
        int operations = 0;
        for (int i = 0; i < scale; i++) {
            NetworkEvent event = event(i, base);
            for (Detector detector : detectors) {
                detector.analyze(event);
                operations++;
            }
        }
        return new Result("detection.analyze", operations, System.nanoTime() - started);
    }

    private static Result featureExtraction(int scale) {
        FlowRecorder recorder = new FlowRecorder();
        Instant base = Instant.parse("2026-01-01T00:00:00Z");
        for (int i = 0; i < 64; i++) {
            recorder.accept(event(i, base));
        }
        var flows = recorder.query(pk.ooad.ntd.flows.FlowQuery.all(64));
        if (flows.isEmpty()) {
            return new Result("ml.features", 0, 0);
        }
        long started = System.nanoTime();
        int operations = 0;
        for (int i = 0; i < scale; i++) {
            FeatureVector.of(flows.get(i % flows.size()));
            operations++;
        }
        return new Result("ml.features", operations, System.nanoTime() - started);
    }

    private static Result anomalyTraining(int scale) {
        List<FlowFeatures> samples = new ArrayList<>();
        Instant base = Instant.parse("2026-01-01T00:00:00Z");
        FlowRecorder recorder = new FlowRecorder();
        int wanted = Math.max(200, Math.min(scale, 2000));
        for (int i = 0; i < wanted; i++) {
            recorder.accept(event(i, base));
        }
        for (var flow : recorder.query(pk.ooad.ntd.flows.FlowQuery.all(wanted))) {
            samples.add(FeatureVector.of(flow));
        }
        while (samples.size() < 2) {
            samples.add(FeatureVector.of(syntheticFlow(samples.size())));
        }
        long started = System.nanoTime();
        AnomalyModel.train(samples, 4, 30, 42L);
        return new Result("ml.kmeans.train(" + samples.size() + ")", 1, System.nanoTime() - started);
    }

    private static Result qualityGate(int scale) {
        AlertQualityGate gate = new AlertQualityGate(true, 60, Severity.LOW, 5000);
        AlertFactory factory = new AlertFactory();
        Instant base = Instant.parse("2026-01-01T00:00:00Z");
        long started = System.nanoTime();
        for (int i = 0; i < scale; i++) {
            Alert alert = factory.create(Severity.LOW, AttackType.PORT_SCAN,
                    "10.0." + (i / 250) + "." + (i % 250), "10.1.0.1",
                    "bench", "benchmark row", base.plusMillis(i));
            gate.allow(alert);
        }
        return new Result("alerts.quality-gate", scale, System.nanoTime() - started);
    }

    private static NetworkEvent event(int index, Instant base) {
        String source = "10.0." + ((index / 200) % 20) + "." + (index % 200);
        String target = "10.1.0." + (1 + (index % 8));
        int port = 1024 + (index % 40);
        EventType type = EventType.values()[index % EventType.values().length];
        return new NetworkEvent(index, base.plusMillis(index * 5L), source, target, port,
                200 + (index % 900), type, index % 11 != 0, "NORMAL", true);
    }

    private static pk.ooad.ntd.flows.FlowRecord syntheticFlow(int index) {
        Instant start = Instant.parse("2026-01-01T00:00:00Z").plusSeconds(index);
        return new pk.ooad.ntd.flows.FlowRecord("f" + index, "10.0.0." + (index % 200),
                "10.1.0.1", 1024 + (index % 40), 80, "TCP",
                100 + index, 0, 1 + (index % 10), start, start.plusMillis(500 + index),
                List.of("OK"), "NORMAL", true, true);
    }
}
