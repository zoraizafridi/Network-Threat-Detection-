package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class AnomalyDetector extends Detector {
    private double zThreshold;
    private int warmupCount;
    private final List<String> allowlist;
    private final Map<String, RunningStats> stats;

    public AnomalyDetector(String name, double zThreshold, int warmupCount, List<String> allowlist) {
        super(name != null ? name : "AnomalyDetector");
        this.zThreshold = zThreshold;
        this.warmupCount = warmupCount;
        this.allowlist = cleaned(allowlist);
        this.stats = new ConcurrentHashMap<>();
    }

    public AnomalyDetector(String name, double zThreshold, int warmupCount) {
        this(name, zThreshold, warmupCount, List.of());
    }

    public AnomalyDetector() {
        this("AnomalyDetector",
            ConfigManager.getInstance().getDouble("detection.anomaly.zThreshold", 3.0),
            ConfigManager.getInstance().getInt("detection.anomaly.warmupCount", 5),
            ConfigManager.getInstance().getList("detection.anomaly.allowlist"));
    }

    private static List<String> cleaned(List<String> entries) {
        List<String> kept = new ArrayList<>();
        if (entries != null) {
            for (String entry : entries) {
                if (entry != null && !entry.isBlank()) {
                    kept.add(entry.trim());
                }
            }
        }
        return List.copyOf(kept);
    }

    @Override
    public synchronized Optional<Alert> analyze(NetworkEvent e) {
        if (e == null || e.type() != EventType.DATA_TRANSFER) {
            return Optional.empty();
        }
        if (listed(allowlist, e.sourceIp()) || listed(allowlist, e.destIp())) {
            return Optional.empty();
        }

        RunningStats hostStats = stats.computeIfAbsent(e.sourceIp(), k -> new RunningStats());
        double value = (double) e.bytes();

        if (hostStats.getCount() < warmupCount) {
            hostStats.update(value);
            return Optional.empty();
        }

        double z = hostStats.zScore(value);
        if (z > zThreshold) {
            Alert alert = alertFactory.create(
                Severity.CRITICAL,
                AttackType.DATA_TRANSFER,
                e.sourceIp(),
                e.destIp(),
                getName(),
                "Volume anomaly detected: z-score " + String.format("%.2f", z) + " > " + zThreshold,
                e.timestamp()
            );
            return Optional.of(alert);
        } else {
            hostStats.update(value);
            return Optional.empty();
        }
    }

    @Override
    public synchronized void reset() {
        stats.clear();
    }

    public double getZThreshold() {
        return zThreshold;
    }

    public void setZThreshold(double zThreshold) {
        this.zThreshold = zThreshold;
    }

    public int getWarmupCount() {
        return warmupCount;
    }

    public void setWarmupCount(int warmupCount) {
        this.warmupCount = warmupCount;
    }

    public Map<String, RunningStats> getStats() {
        return Collections.unmodifiableMap(stats);
    }
}
