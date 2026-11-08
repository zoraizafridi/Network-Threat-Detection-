package pk.ooad.ntd.ml;

import java.util.Arrays;
import java.util.List;

public final class AnomalyModel {

    private static final double EPSILON = 1e-9;

    private final double[] mean;
    private final double[] deviation;
    private final double[][] centroids;
    private final double[] sortedDistances;
    private final double scale;
    private final int samples;

    private AnomalyModel(double[] mean, double[] deviation, double[][] centroids,
                         double[] sortedDistances, double scale, int samples) {
        this.mean = mean;
        this.deviation = deviation;
        this.centroids = centroids;
        this.sortedDistances = sortedDistances;
        this.scale = scale;
        this.samples = samples;
    }

    public static AnomalyModel train(List<FlowFeatures> samples, int k, int maxIterations, long seed) {
        if (samples == null || samples.size() < 2) {
            throw new IllegalArgumentException("At least two samples are required to train");
        }
        int dimensions = FlowFeatures.SIZE;
        int count = samples.size();
        double[] mean = new double[dimensions];
        for (FlowFeatures sample : samples) {
            for (int d = 0; d < dimensions; d++) {
                mean[d] += sample.value(d);
            }
        }
        for (int d = 0; d < dimensions; d++) {
            mean[d] /= count;
        }
        double[] deviation = new double[dimensions];
        for (FlowFeatures sample : samples) {
            for (int d = 0; d < dimensions; d++) {
                double delta = sample.value(d) - mean[d];
                deviation[d] += delta * delta;
            }
        }
        for (int d = 0; d < dimensions; d++) {
            deviation[d] = Math.sqrt(deviation[d] / count);
            if (deviation[d] < EPSILON) {
                deviation[d] = 1.0;
            }
        }

        double[][] standardized = new double[count][];
        for (int i = 0; i < count; i++) {
            standardized[i] = standardize(samples.get(i), mean, deviation);
        }
        KMeans.Result result = KMeans.fit(standardized, k, maxIterations, seed);
        double[] distances = new double[count];
        for (int i = 0; i < count; i++) {
            distances[i] = KMeans.nearestDistance(standardized[i], result.centroids());
        }
        double[] sortedDistances = distances.clone();
        Arrays.sort(sortedDistances);
        double scale = percentile(distances, 0.95);
        if (scale < EPSILON) {
            double total = 0;
            for (double distance : distances) {
                total += distance;
            }
            scale = Math.max(EPSILON, total / count);
        }
        return new AnomalyModel(mean, deviation, result.centroids(), sortedDistances, scale, count);
    }

    public double score(FlowFeatures features) {
        if (features == null || sortedDistances.length == 0) {
            return 0.0;
        }
        double distance = distance(features);
        int below = lowerBound(sortedDistances, distance);
        int equal = upperBound(sortedDistances, distance) - below;
        double rank = (below + 0.5 * equal) / sortedDistances.length;
        return Math.max(0.0, Math.min(1.0, rank));
    }

    public double distance(FlowFeatures features) {
        return KMeans.nearestDistance(standardize(features, mean, deviation), centroids);
    }

    public int clusters() {
        return centroids.length;
    }

    public int samples() {
        return samples;
    }

    public double scale() {
        return scale;
    }

    private static double[] standardize(FlowFeatures features, double[] mean, double[] deviation) {
        double[] values = features.values();
        double[] result = new double[values.length];
        for (int d = 0; d < values.length; d++) {
            result[d] = (values[d] - mean[d]) / deviation[d];
        }
        return result;
    }

    private static double percentile(double[] values, double fraction) {
        double[] sorted = values.clone();
        Arrays.sort(sorted);
        int index = (int) Math.ceil(fraction * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, index))];
    }

    private static int lowerBound(double[] sorted, double target) {
        int low = 0;
        int high = sorted.length;
        while (low < high) {
            int mid = (low + high) >>> 1;
            if (sorted[mid] < target) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return low;
    }

    private static int upperBound(double[] sorted, double target) {
        int low = 0;
        int high = sorted.length;
        while (low < high) {
            int mid = (low + high) >>> 1;
            if (sorted[mid] <= target) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return low;
    }
}
