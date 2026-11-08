package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class BeaconingDetector extends Detector {

    private static final class Series {
        private Instant last;
        private int samples;
        private double mean;
        private double m2;
        private Instant lastAlert;
    }

    private final boolean enabled;
    private final int minSamples;
    private final double jitterTolerance;
    private final long minIntervalMillis;
    private final long maxIntervalMillis;
    private final int maxTracked;
    private final long cooldownMillis;
    private final List<String> allowlist;
    private final Map<String, Series> series = new HashMap<>();

    public BeaconingDetector() {
        this("BeaconingDetector", ConfigManager.getInstance());
    }

    public BeaconingDetector(String name, ConfigManager config) {
        this(name,
                Boolean.parseBoolean(config.getString("detection.beaconing.enabled", "false")),
                config.getInt("detection.beaconing.minSamples", 4),
                config.getDouble("detection.beaconing.jitterTolerance", 0.25),
                config.getInt("detection.beaconing.minIntervalSeconds", 5),
                config.getInt("detection.beaconing.maxIntervalSeconds", 900),
                config.getInt("detection.beaconing.maxTracked", 2000),
                config.getInt("detection.beaconing.cooldownSeconds", 300),
                config.getList("detection.beaconing.allowlist"));
    }

    BeaconingDetector(String name, boolean enabled, int minSamples, double jitterTolerance,
                      int minIntervalSeconds, int maxIntervalSeconds, int maxTracked, int cooldownSeconds) {
        this(name, enabled, minSamples, jitterTolerance, minIntervalSeconds, maxIntervalSeconds, maxTracked,
                cooldownSeconds, List.of());
    }

    BeaconingDetector(String name, boolean enabled, int minSamples, double jitterTolerance,
                      int minIntervalSeconds, int maxIntervalSeconds, int maxTracked, int cooldownSeconds,
                      List<String> allowlist) {
        super(name != null ? name : "BeaconingDetector");
        this.enabled = enabled;
        this.minSamples = Math.max(3, minSamples);
        this.jitterTolerance = Math.max(0.01, jitterTolerance);
        this.minIntervalMillis = Math.max(0, minIntervalSeconds) * 1000L;
        this.maxIntervalMillis = Math.max(this.minIntervalMillis + 1000L, maxIntervalSeconds * 1000L);
        this.maxTracked = Math.max(16, maxTracked);
        this.cooldownMillis = Math.max(0, cooldownSeconds) * 1000L;
        List<String> exempt = new ArrayList<>();
        if (allowlist != null) {
            for (String entry : allowlist) {
                if (entry != null && !entry.isBlank()) {
                    exempt.add(entry.trim());
                }
            }
        }
        this.allowlist = List.copyOf(exempt);
    }

    @Override
    public synchronized Optional<Alert> analyze(NetworkEvent e) {
        if (!enabled || e == null || e.timestamp() == null) {
            return Optional.empty();
        }
        if (listed(allowlist, e.sourceIp()) || listed(allowlist, e.destIp())) {
            return Optional.empty();
        }
        String key = e.sourceIp() + '|' + e.destIp() + '|' + e.port();
        Series sample = series.get(key);
        if (sample == null) {
            if (series.size() >= maxTracked) {
                evictOldest();
            }
            sample = new Series();
            series.put(key, sample);
        }
        Instant now = e.timestamp();
        if (sample.last != null) {
            long interval = Duration.between(sample.last, now).toMillis();
            if (interval < 0) {
                sample.samples = 0;
                sample.mean = 0;
                sample.m2 = 0;
            } else {
                sample.samples++;
                double delta = interval - sample.mean;
                sample.mean += delta / sample.samples;
                sample.m2 += delta * (interval - sample.mean);
            }
        }
        sample.last = now;

        if (sample.samples < minSamples || sample.mean < minIntervalMillis || sample.mean > maxIntervalMillis) {
            return Optional.empty();
        }
        double variance = sample.m2 / Math.max(1, sample.samples - 1);
        double deviation = Math.sqrt(Math.max(0, variance));
        double jitter = sample.mean <= 0 ? Double.MAX_VALUE : deviation / sample.mean;
        if (jitter > jitterTolerance) {
            return Optional.empty();
        }
        if (sample.lastAlert != null && Duration.between(sample.lastAlert, now).toMillis() < cooldownMillis) {
            return Optional.empty();
        }
        sample.lastAlert = now;
        long seconds = Math.round(sample.mean / 1000.0);
        String description = "Periodic contacts from " + e.sourceIp() + " to " + e.destIp() + ':' + e.port()
                + " every ~" + seconds + "s over " + sample.samples + " intervals (jitter "
                + Math.round(jitter * 100) + "%)";
        return Optional.of(alertFactory.create(
                Severity.HIGH,
                AttackType.PORT_SCAN,
                e.sourceIp(),
                e.destIp(),
                getName(),
                description,
                now));
    }

    @Override
    public synchronized void reset() {
        series.clear();
    }

    public synchronized int trackedSeries() {
        return series.size();
    }

    public boolean isEnabled() {
        return enabled;
    }

    private void evictOldest() {
        String oldestKey = null;
        Instant oldest = null;
        for (Map.Entry<String, Series> entry : series.entrySet()) {
            Instant seen = entry.getValue().last;
            if (seen != null && (oldest == null || seen.isBefore(oldest))) {
                oldest = seen;
                oldestKey = entry.getKey();
            }
        }
        if (oldestKey != null) {
            series.remove(oldestKey);
        } else {
            series.clear();
        }
    }
}
