package pk.ooad.ntd.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunningStatsTest {

    @Test
    @DisplayName("Welford method: RunningStats correctly computes count, mean, m2, and stdDev")
    void testWelfordComputation() {
        RunningStats stats = new RunningStats();
        assertEquals(0, stats.getCount());
        assertEquals(0.0, stats.getMean());
        assertEquals(0.0, stats.getM2());
        assertEquals(0.0, stats.getStdDev());

        stats.update(10.0);
        assertEquals(1, stats.getCount());
        assertEquals(10.0, stats.getMean());
        assertEquals(0.0, stats.getM2());
        assertEquals(0.0, stats.getStdDev(), "StdDev must be 0 for a single value");

        // Second value: sample variance for [10, 20] is 50, stdDev is ~7.071
        stats.update(20.0);
        assertEquals(2, stats.getCount());
        assertEquals(15.0, stats.getMean());
        assertEquals(50.0, stats.getM2());
        assertEquals(Math.sqrt(50.0), stats.getStdDev(), 1e-6);

        // Third value: [10, 20, 30] -> mean = 20, sample variance = 100, stdDev = 10
        stats.update(30.0);
        assertEquals(3, stats.getCount());
        assertEquals(20.0, stats.getMean());
        assertEquals(200.0, stats.getM2());
        assertEquals(10.0, stats.getStdDev(), 1e-6);
    }

    @Test
    @DisplayName("zScore specification: Returns 0.0 when standard deviation is 0")
    void testZScoreWhenStdDevIsZero() {
        RunningStats stats = new RunningStats();

        assertEquals(0.0, stats.zScore(100.0), "zScore must be 0 when empty");

        stats.update(50.0);
        assertEquals(0.0, stats.zScore(50.0));
        assertEquals(0.0, stats.zScore(100.0), "zScore must be 0 when stdDev is 0");

        stats.update(50.0);
        stats.update(50.0);
        assertEquals(0.0, stats.getStdDev());
        assertEquals(0.0, stats.zScore(100.0), "zScore must be 0 when all values are identical");
    }

    @Test
    @DisplayName("zScore calculation and reset contract")
    void testZScoreCalculationAndReset() {
        RunningStats stats = new RunningStats();
        // [10, 20, 30] -> mean = 20, stdDev = 10
        stats.update(10.0);
        stats.update(20.0);
        stats.update(30.0);

        assertEquals(0.0, stats.zScore(20.0), 1e-6);
        assertEquals(1.0, stats.zScore(30.0), 1e-6);
        assertEquals(3.0, stats.zScore(50.0), 1e-6);
        assertEquals(-2.0, stats.zScore(0.0), 1e-6);

        stats.reset();
        assertEquals(0, stats.getCount());
        assertEquals(0.0, stats.getMean());
        assertEquals(0.0, stats.getM2());
        assertEquals(0.0, stats.getStdDev());
    }
}

