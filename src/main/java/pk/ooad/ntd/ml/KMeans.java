package pk.ooad.ntd.ml;

import java.util.Arrays;
import java.util.Random;

/**
 * Lloyd's k-means over a fixed number of dimensions, initialised with k-means++.
 *
 * <p>Written here rather than pulled in as a dependency because the requirement
 * is pure Java and because a model an operator cannot inspect is a model they
 * cannot trust. Nothing is random after construction: the seed is explicit, and
 * the same seed and points produce the same centroids.</p>
 *
 * <p>An empty cluster is re-seeded at the point currently farthest from its
 * centroid. Doing nothing there would silently reduce the number of clusters,
 * which reads later like "the data had fewer shapes than it did".</p>
 */
public final class KMeans {

    public record Result(double[][] centroids, int[] assignments, double inertia, int iterations) {
    }

    private KMeans() {
    }

    public static Result fit(double[][] points, int k, int maxIterations, long seed) {
        if (points == null || points.length == 0) {
            throw new IllegalArgumentException("At least one point is required");
        }
        int dimensions = points[0].length;
        for (double[] point : points) {
            if (point == null || point.length != dimensions) {
                throw new IllegalArgumentException("Points must share one dimension");
            }
        }
        int clusters = Math.max(1, Math.min(k, points.length));
        double[][] centroids = initPlusPlus(points, clusters, new Random(seed));
        int[] assignments = new int[points.length];
        Arrays.fill(assignments, -1);
        double inertia = 0;
        int iterations = 0;
        boolean changed = true;

        while (changed && iterations < Math.max(1, maxIterations)) {
            changed = false;
            inertia = 0;
            for (int i = 0; i < points.length; i++) {
                int best = 0;
                double bestDistance = Double.MAX_VALUE;
                for (int c = 0; c < clusters; c++) {
                    double distance = squaredDistance(points[i], centroids[c]);
                    if (distance < bestDistance) {
                        bestDistance = distance;
                        best = c;
                    }
                }
                if (assignments[i] != best) {
                    assignments[i] = best;
                    changed = true;
                }
                inertia += bestDistance;
            }

            double[][] sums = new double[clusters][dimensions];
            int[] counts = new int[clusters];
            for (int i = 0; i < points.length; i++) {
                int cluster = assignments[i];
                counts[cluster]++;
                for (int d = 0; d < dimensions; d++) {
                    sums[cluster][d] += points[i][d];
                }
            }
            for (int c = 0; c < clusters; c++) {
                if (counts[c] == 0) {
                    int farthest = farthestPoint(points, centroids);
                    centroids[c] = points[farthest].clone();
                } else {
                    for (int d = 0; d < dimensions; d++) {
                        centroids[c][d] = sums[c][d] / counts[c];
                    }
                }
            }
            iterations++;
        }
        return new Result(centroids, assignments, inertia, iterations);
    }

    /** Distance from a point to its nearest centroid. */
    public static double nearestDistance(double[] point, double[][] centroids) {
        double best = Double.MAX_VALUE;
        for (double[] centroid : centroids) {
            best = Math.min(best, squaredDistance(point, centroid));
        }
        return Math.sqrt(best);
    }

    static double squaredDistance(double[] left, double[] right) {
        double sum = 0;
        for (int i = 0; i < left.length; i++) {
            double delta = left[i] - right[i];
            sum += delta * delta;
        }
        return sum;
    }

    private static double[][] initPlusPlus(double[][] points, int clusters, Random random) {
        double[][] centroids = new double[clusters][];
        centroids[0] = points[random.nextInt(points.length)].clone();
        double[] nearest = new double[points.length];
        Arrays.fill(nearest, Double.MAX_VALUE);
        for (int c = 1; c < clusters; c++) {
            double total = 0;
            for (int i = 0; i < points.length; i++) {
                nearest[i] = Math.min(nearest[i], squaredDistance(points[i], centroids[c - 1]));
                total += nearest[i];
            }
            if (total <= 0) {
                // Every point is identical to a chosen centroid; spread the rest
                // over the same points rather than dividing by zero.
                centroids[c] = points[random.nextInt(points.length)].clone();
                continue;
            }
            double target = random.nextDouble() * total;
            int chosen = points.length - 1;
            double running = 0;
            for (int i = 0; i < points.length; i++) {
                running += nearest[i];
                if (running >= target) {
                    chosen = i;
                    break;
                }
            }
            centroids[c] = points[chosen].clone();
        }
        return centroids;
    }

    private static int farthestPoint(double[][] points, double[][] centroids) {
        int farthest = 0;
        double best = -1;
        for (int i = 0; i < points.length; i++) {
            double distance = nearestDistance(points[i], centroids);
            if (distance > best) {
                best = distance;
                farthest = i;
            }
        }
        return farthest;
    }
}
