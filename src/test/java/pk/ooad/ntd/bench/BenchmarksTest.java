package pk.ooad.ntd.bench;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BenchmarksTest {

    @Test
    @DisplayName("Every measurement runs and reports a positive operation count")
    void measurementsAreSelfDescribing() {
        List<Benchmarks.Result> results = Benchmarks.run(200);
        assertEquals(5, results.size());

        List<String> names = new ArrayList<>();
        for (Benchmarks.Result result : results) {
            names.add(result.name());
            assertTrue(result.operations() > 0, result.name() + " must count its operations");
            assertTrue(result.elapsedNanos() >= 0);
            assertTrue(result.microsPerOperation() >= 0);
            assertTrue(result.operationsPerSecond() >= 0);
            assertTrue(result.line().contains(String.valueOf(result.operations())));
        }
        assertTrue(names.contains("flow-recorder.accept"));
        assertTrue(names.contains("detection.analyze"));
        assertTrue(names.contains("ml.features"));
        assertTrue(names.contains("alerts.quality-gate"));
        assertTrue(names.stream().anyMatch(name -> name.startsWith("ml.kmeans.train(")));
    }

    @Test
    @DisplayName("Two runs measure the same operations, so rows can be compared")
    void operationCountsAreRepeatable() {
        List<String> first = new ArrayList<>();
        for (Benchmarks.Result result : Benchmarks.run(300)) {
            first.add(result.name() + "=" + result.operations());
        }
        List<String> second = new ArrayList<>();
        for (Benchmarks.Result result : Benchmarks.run(300)) {
            second.add(result.name() + "=" + result.operations());
        }
        assertEquals(first, second);
    }

    @Test
    @DisplayName("The report is a header plus one line per measurement")
    void reportIsTabular() {
        List<Benchmarks.Result> results = Benchmarks.run(200);
        String report = Benchmarks.report(results);
        String[] lines = report.split("\\R");
        assertEquals(1 + 1 + results.size(), lines.length);
        assertTrue(lines[0].startsWith("Benchmark report"));
        assertTrue(lines[1].contains("ops/op") || lines[1].contains("us/op"));
        assertTrue(lines[1].contains("ops/s"));
        assertTrue(report.contains("flow-recorder.accept"));
    }

    @Test
    @DisplayName("A zero-operation result reports zero rather than dividing by zero")
    void zeroOperationsAreSafe() {
        Benchmarks.Result empty = new Benchmarks.Result("nothing", 0, 0);
        assertEquals(0.0, empty.microsPerOperation());
        assertEquals(0.0, empty.operationsPerSecond());
        assertTrue(empty.line().startsWith("nothing"));

        Benchmarks.Result instant = new Benchmarks.Result("instant", 10, 0);
        assertEquals(0.0, instant.microsPerOperation());
        assertEquals(0.0, instant.operationsPerSecond());
    }

    @Test
    @DisplayName("A tiny scale is raised to the minimum so the numbers mean something")
    void smallScaleIsRaised() {
        List<Benchmarks.Result> results = Benchmarks.run(1);
        assertEquals(5, results.size());
        Benchmarks.Result recorder = results.get(0);
        assertEquals("flow-recorder.accept", recorder.name());
        assertEquals(200, recorder.operations(), "scale is clamped to at least 200");
    }
}
