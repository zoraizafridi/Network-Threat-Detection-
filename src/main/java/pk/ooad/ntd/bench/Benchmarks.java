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
import pk.ooad.ntd.flows.FlowQuery;
import pk.ooad.ntd.flows.FlowRecorder;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.ml.AnomalyModel;
import pk.ooad.ntd.ml.FeatureVector;
import pk.ooad.ntd.ml.FlowFeatures;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public final class Benchmarks {

    public static final int DEFAULT_EVENTS = 10_000;

    public static final int DEFAULT_ROUNDS = 5;

    private static final Instant BASE = Instant.parse("2026-01-01T00:00:00Z");

    public record Result(String name, long operations, int rounds, long samples,
                         double meanMicros, double p50Micros, double p95Micros, double p99Micros,
                         double maxMicros, double operationsPerSecond) {

        public Result {
            if (rounds < 0 || samples < 0 || operations < 0) {
                throw new IllegalArgumentException("a result counts forward only");
            }
        }

        public static Result empty(String name) {
            return new Result(name, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        }

        public double microsPerOperation() {
            return meanMicros;
        }

        public String line() {
            return String.format(Locale.ROOT,
                    "%-27s %9d %6d %10.2f %10.2f %10.2f %10.2f %10.2f %14.0f",
                    name, operations, rounds, meanMicros, p50Micros, p95Micros, p99Micros, maxMicros,
                    operationsPerSecond);
        }
    }

    private Benchmarks() {
    }

    public static List<Result> run(int scale) {
        int size = Math.max(200, scale);
        List<Result> results = new ArrayList<>();
        results.add(flowRecorderAccept(size));
        results.add(detectorAnalyze("detection.analyze", new DetectorFactory().createAll(), size));
        results.add(detectorAnalyze("detection.ndr.analyze", new DetectorFactory().createNdr(), size));
        results.add(featureExtraction(size));
        results.add(anomalyTraining(size));
        results.add(qualityGate(size));
        return results;
    }

    public static String report(List<Result> results) {
        StringBuilder out = new StringBuilder("Benchmark report, ")
                .append(rounds()).append(" timed rounds per row, warm-up discarded")
                .append(System.lineSeparator());
        out.append(String.format(Locale.ROOT, "%-27s %9s %6s %10s %10s %10s %10s %10s %14s",
                "benchmark", "ops", "rounds", "mean us/op", "p50 us/op", "p95 us/op", "p99 us/op",
                "max us/op", "ops/s"))
                .append(System.lineSeparator());
        for (Result result : results) {
            out.append(result.line()).append(System.lineSeparator());
        }
        return out.toString();
    }

    private static int rounds() {
        return Math.max(1, Math.min(20, ConfigManager.getInstance().getInt("bench.rounds", DEFAULT_ROUNDS)));
    }

    private static int warmth(int scale) {
        return Math.max(1, scale / 10);
    }

    private static Result flowRecorderAccept(int scale) {
        Tally tally = new Tally("flow-recorder.accept");
        FlowRecorder warm = new FlowRecorder();
        for (int i = 0; i < warmth(scale); i++) {
            warm.accept(event(i, BASE));
        }
        for (int round = 0; round < tally.rounds(); round++) {
            FlowRecorder recorder = new FlowRecorder();
            for (int i = 0; i < scale; i++) {
                NetworkEvent event = event(i, BASE);
                long started = System.nanoTime();
                recorder.accept(event);
                tally.add(System.nanoTime() - started);
            }
        }
        return tally.result(scale);
    }

    private static Result detectorAnalyze(String name, List<Detector> detectors, int scale) {
        for (int i = 0; i < warmth(scale); i++) {
            NetworkEvent event = event(i, BASE);
            for (Detector detector : detectors) {
                detector.analyze(event);
            }
        }
        Tally tally = new Tally(name);
        for (int round = 0; round < tally.rounds(); round++) {
            for (Detector detector : detectors) {
                detector.reset();
            }
            for (int i = 0; i < scale; i++) {
                NetworkEvent event = event(i, BASE);
                for (Detector detector : detectors) {
                    long started = System.nanoTime();
                    detector.analyze(event);
                    tally.add(System.nanoTime() - started);
                }
            }
        }
        return tally.result((long) scale * detectors.size());
    }

    private static Result featureExtraction(int scale) {
        FlowRecorder recorder = new FlowRecorder();
        for (int i = 0; i < 64; i++) {
            recorder.accept(event(i, BASE));
        }
        List<FlowRecord> flows = recorder.query(FlowQuery.all(64));
        if (flows.isEmpty()) {
            return Result.empty("ml.features");
        }
        for (int i = 0; i < warmth(scale); i++) {
            FeatureVector.of(flows.get(i % flows.size()));
        }
        Tally tally = new Tally("ml.features");
        for (int round = 0; round < tally.rounds(); round++) {
            for (int i = 0; i < scale; i++) {
                FlowRecord flow = flows.get(i % flows.size());
                long started = System.nanoTime();
                FeatureVector.of(flow);
                tally.add(System.nanoTime() - started);
            }
        }
        return tally.result(scale);
    }

    private static Result anomalyTraining(int scale) {
        List<FlowFeatures> samples = new ArrayList<>();
        int wanted = Math.max(200, Math.min(scale, 2000));
        FlowRecorder recorder = new FlowRecorder();
        for (int i = 0; i < wanted; i++) {
            recorder.accept(event(i, BASE));
        }
        for (FlowRecord flow : recorder.query(FlowQuery.all(wanted))) {
            samples.add(FeatureVector.of(flow));
        }
        while (samples.size() < 2) {
            samples.add(FeatureVector.of(syntheticFlow(samples.size())));
        }
        AnomalyModel.train(samples.subList(0, Math.max(2, samples.size() / 10)), 4, 30, 42L);
        Tally tally = new Tally("ml.kmeans.train(" + samples.size() + ")");
        for (int round = 0; round < tally.rounds(); round++) {
            long started = System.nanoTime();
            AnomalyModel.train(samples, 4, 30, 42L);
            tally.add(System.nanoTime() - started);
        }
        return tally.result(1);
    }

    private static Result qualityGate(int scale) {
        AlertFactory factory = new AlertFactory();
        AlertQualityGate warm = new AlertQualityGate(true, 60, Severity.LOW, 5000);
        for (int i = 0; i < warmth(scale); i++) {
            warm.allow(alert(factory, i));
        }
        Tally tally = new Tally("alerts.quality-gate");
        for (int round = 0; round < tally.rounds(); round++) {
            AlertQualityGate gate = new AlertQualityGate(true, 60, Severity.LOW, 5000);
            for (int i = 0; i < scale; i++) {
                Alert alert = alert(factory, i);
                long started = System.nanoTime();
                gate.allow(alert);
                tally.add(System.nanoTime() - started);
            }
        }
        return tally.result(scale);
    }

    private static Alert alert(AlertFactory factory, int index) {
        return factory.create(Severity.LOW, AttackType.PORT_SCAN,
                "10.0." + (index / 250) + "." + (index % 250), "10.1.0.1",
                "bench", "benchmark row", BASE.plusMillis(index));
    }

    private static NetworkEvent event(int index, Instant base) {
        String source = "10.0." + ((index / 200) % 20) + "." + (index % 200);
        String target = "10.1.0." + (1 + (index % 8));
        int port = 1024 + (index % 40);
        EventType type = EventType.values()[index % EventType.values().length];
        return new NetworkEvent(index, base.plusMillis(index * 5L), source, target, port,
                200 + (index % 900), type, index % 11 != 0, "NORMAL", true);
    }

    private static FlowRecord syntheticFlow(int index) {
        Instant start = BASE.plusSeconds(index);
        return new FlowRecord("f" + index, "10.0.0." + (index % 200),
                "10.1.0.1", 1024 + (index % 40), 80, "TCP",
                100 + index, 0, 1 + (index % 10), start, start.plusMillis(500 + index),
                List.of("OK"), "NORMAL", true, true);
    }

    private static final class Tally {
        private final String name;
        private final int rounds;
        private long[] samples = new long[1024];
        private int count;
        private long totalNanos;

        private Tally(String name) {
            this.name = name;
            this.rounds = Benchmarks.rounds();
        }

        private int rounds() {
            return rounds;
        }

        private void add(long nanos) {
            if (count == samples.length) {
                samples = Arrays.copyOf(samples, samples.length * 2);
            }
            samples[count++] = Math.max(0L, nanos);
            totalNanos += Math.max(0L, nanos);
        }

        private Result result(long operationsPerRound) {
            if (count == 0 || totalNanos <= 0) {
                return new Result(name, operationsPerRound, rounds, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
            }
            long[] sorted = Arrays.copyOf(samples, count);
            Arrays.sort(sorted);
            double mean = totalNanos / 1000.0 / count;
            double perSecond = count * 1_000_000_000.0 / totalNanos;
            return new Result(name, operationsPerRound, rounds, count, mean,
                    percentile(sorted, 0.50), percentile(sorted, 0.95), percentile(sorted, 0.99),
                    sorted[sorted.length - 1] / 1000.0, perSecond);
        }

        private static double percentile(long[] sorted, double fraction) {
            if (sorted.length == 0) {
                return 0.0;
            }
            int rank = (int) Math.ceil(fraction * sorted.length);
            int index = Math.min(sorted.length - 1, Math.max(0, rank - 1));
            return sorted[index] / 1000.0;
        }
    }
}
