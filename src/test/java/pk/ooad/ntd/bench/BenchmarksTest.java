package pk.ooad.ntd.bench;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BenchmarksTest {

    @Test
    @DisplayName("Every measurement runs, counts its work and reports ordered percentiles")
    void measurementsAreSelfDescribing() {
        List<Benchmarks.Result> results = Benchmarks.run(200);
        assertEquals(6, results.size());

        List<String> names = new ArrayList<>();
        for (Benchmarks.Result result : results) {
            names.add(result.name());
            assertTrue(result.operations() > 0, result.name() + " must count its operations");
            assertTrue(result.rounds() >= 1, result.name() + " must report its rounds");
            assertTrue(result.samples() > 0, result.name() + " must keep its samples");
            assertTrue(result.meanMicros() > 0, result.name() + " must take time");
            assertTrue(result.operationsPerSecond() > 0);
            assertTrue(result.p50Micros() <= result.p95Micros(), result.name() + " p50 must not exceed p95");
            assertTrue(result.p95Micros() <= result.p99Micros(), result.name() + " p95 must not exceed p99");
            assertTrue(result.p99Micros() <= result.maxMicros(), result.name() + " p99 must not exceed max");
            assertTrue(result.line().contains(String.valueOf(result.operations())));
        }
        assertTrue(names.contains("flow-recorder.accept"));
        assertTrue(names.contains("detection.analyze"));
        assertTrue(names.contains("detection.ndr.analyze"));
        assertTrue(names.contains("ml.features"));
        assertTrue(names.contains("alerts.quality-gate"));
        assertTrue(names.stream().anyMatch(name -> name.startsWith("ml.kmeans.train(")));
    }

    @Test
    @DisplayName("Two runs measure the same operations, so rows can be compared")
    void operationCountsAreRepeatable() {
        List<String> first = new ArrayList<>();
        for (Benchmarks.Result result : Benchmarks.run(300)) {
            first.add(result.name() + "=" + result.operations() + "x" + result.rounds());
        }
        List<String> second = new ArrayList<>();
        for (Benchmarks.Result result : Benchmarks.run(300)) {
            second.add(result.name() + "=" + result.operations() + "x" + result.rounds());
        }
        assertEquals(first, second);
    }

    @Test
    @DisplayName("The report is two header lines plus one line per measurement")
    void reportIsTabular() {
        List<Benchmarks.Result> results = Benchmarks.run(200);
        String report = Benchmarks.report(results);
        String[] lines = report.split("\\R");
        assertEquals(2 + results.size(), lines.length);
        assertTrue(lines[0].startsWith("Benchmark report"));
        assertTrue(lines[1].contains("us/op"));
        assertTrue(lines[1].contains("ops/s"));
        assertTrue(lines[1].contains("p95"));
        assertTrue(report.contains("flow-recorder.accept"));
    }

    @Test
    @DisplayName("An empty result reports zero rather than dividing by zero")
    void zeroOperationsAreSafe() {
        Benchmarks.Result empty = Benchmarks.Result.empty("nothing");
        assertEquals(0L, empty.operations());
        assertEquals(0.0, empty.microsPerOperation());
        assertEquals(0.0, empty.operationsPerSecond());
        assertEquals(0.0, empty.p99Micros());
        assertTrue(empty.line().startsWith("nothing"));

        Benchmarks.Result instant = new Benchmarks.Result("instant", 10, 5, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        assertEquals(0.0, instant.microsPerOperation());
        assertEquals(0.0, instant.operationsPerSecond());
    }

    @Test
    @DisplayName("A tiny scale is raised to the minimum so the numbers mean something")
    void smallScaleIsRaised() {
        List<Benchmarks.Result> results = Benchmarks.run(1);
        assertEquals(6, results.size());
        Benchmarks.Result recorder = results.get(0);
        assertEquals("flow-recorder.accept", recorder.name());
        assertEquals(200, recorder.operations(), "scale is clamped to at least 200");
        assertTrue(recorder.rounds() >= 1);
    }
}
