package pk.ooad.ntd.detection;

public class RunningStats {
    private long count;
    private double mean;
    private double m2;

    public RunningStats() {
        this.count = 0;
        this.mean = 0.0;
        this.m2 = 0.0;
    }

    public synchronized void update(double x) {
        count++;
        double delta = x - mean;
        mean += delta / count;
        double delta2 = x - mean;
        m2 += delta * delta2;
    }

    public synchronized double getStdDev() {
        if (count < 2) {
            return 0.0;
        }
        return Math.sqrt(m2 / (count - 1));
    }

    public synchronized double zScore(double x) {
        double std = getStdDev();
        if (std == 0.0) {
            return 0.0;
        }
        return (x - mean) / std;
    }

    public synchronized long getCount() {
        return count;
    }

    public synchronized double getMean() {
        return mean;
    }

    public synchronized double getM2() {
        return m2;
    }

    public synchronized void reset() {
        this.count = 0;
        this.mean = 0.0;
        this.m2 = 0.0;
    }
}
