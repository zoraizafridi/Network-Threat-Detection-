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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class FloodDetector extends Detector {

    private static final class Window {
        private Instant start;
        private int count;
        private final Set<String> sources = new HashSet<>();
        private Instant lastAlert;
    }

    private final boolean enabled;
    private final long windowMillis;
    private final int maxConnections;
    private final int maxTracked;
    private final long cooldownMillis;
    private final List<String> allowlist;
    private final Map<String, Window> windows = new HashMap<>();

    public FloodDetector() {
        this("FloodDetector", ConfigManager.getInstance());
    }

    public FloodDetector(String name, ConfigManager config) {
        this(name,
                Boolean.parseBoolean(config.getString("detection.flood.enabled", "false")),
                config.getInt("detection.flood.windowSeconds", 60),
                config.getInt("detection.flood.maxConnections", 100),
                config.getInt("detection.flood.maxTracked", 2000),
                config.getInt("detection.flood.cooldownSeconds", 60),
                config.getList("detection.flood.allowlist"));
    }

    FloodDetector(String name, boolean enabled, int windowSeconds, int maxConnections,
                  int maxTracked, int cooldownSeconds) {
        this(name, enabled, windowSeconds, maxConnections, maxTracked, cooldownSeconds, List.of());
    }

    FloodDetector(String name, boolean enabled, int windowSeconds, int maxConnections,
                  int maxTracked, int cooldownSeconds, List<String> allowlist) {
        super(name != null ? name : "FloodDetector");
        this.enabled = enabled;
        this.windowMillis = Math.max(1, windowSeconds) * 1000L;
        this.maxConnections = Math.max(1, maxConnections);
        this.maxTracked = Math.max(16, maxTracked);
        this.cooldownMillis = Math.max(0, cooldownSeconds) * 1000L;
        this.allowlist = cleaned(allowlist);
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
        if (!enabled || e == null || e.timestamp() == null || e.destIp() == null || e.destIp().isBlank()) {
            return Optional.empty();
        }
        if (listed(allowlist, e.destIp()) || listed(allowlist, e.sourceIp())) {
            return Optional.empty();
        }
        String key = e.destIp();
        Window window = windows.get(key);
        if (window == null) {
            if (windows.size() >= maxTracked) {
                evictOldest();
            }
            window = new Window();
            window.start = e.timestamp();
            windows.put(key, window);
        }
        long elapsed = Duration.between(window.start, e.timestamp()).toMillis();
        if (elapsed > windowMillis || elapsed < 0) {
            window.start = e.timestamp();
            window.count = 0;
            window.sources.clear();
        }
        window.count++;
        if (e.sourceIp() != null && !e.sourceIp().isBlank()) {
            window.sources.add(e.sourceIp());
        }
        if (window.count <= maxConnections) {
            return Optional.empty();
        }
        if (window.lastAlert != null && Duration.between(window.lastAlert, e.timestamp()).toMillis() < cooldownMillis) {
            return Optional.empty();
        }
        window.lastAlert = e.timestamp();
        String description = "Connection flood of " + window.count + " connections to " + e.destIp()
                + " from " + window.sources.size() + " distinct sources within "
                + (windowMillis / 1000) + "s (limit " + maxConnections + ")";
        return Optional.of(alertFactory.create(
                Severity.HIGH,
                AttackType.DOS_FLOOD,
                e.sourceIp(),
                e.destIp(),
                getName(),
                description,
                e.timestamp()));
    }

    @Override
    public synchronized void reset() {
        windows.clear();
    }

    public synchronized int trackedDestinations() {
        return windows.size();
    }

    public boolean isEnabled() {
        return enabled;
    }

    private void evictOldest() {
        String oldestKey = null;
        Instant oldest = null;
        for (Map.Entry<String, Window> entry : windows.entrySet()) {
            Instant start = entry.getValue().start;
            if (start != null && (oldest == null || start.isBefore(oldest))) {
                oldest = start;
                oldestKey = entry.getKey();
            }
        }
        if (oldestKey != null) {
            windows.remove(oldestKey);
        } else {
            windows.clear();
        }
    }
}

