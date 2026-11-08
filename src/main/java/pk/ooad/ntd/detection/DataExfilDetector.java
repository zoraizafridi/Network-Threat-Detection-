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

public class DataExfilDetector extends Detector {

    private static final class Window {
        private Instant start;
        private long bytes;
        private Instant lastAlert;
    }

    private final boolean enabled;
    private final long windowMillis;
    private final long maxBytes;
    private final int maxTracked;
    private final long cooldownMillis;
    private final List<String> allowlist;
    private final List<String> internalPrefixes;
    private final Map<String, Window> windows = new HashMap<>();

    public DataExfilDetector() {
        this("DataExfilDetector", ConfigManager.getInstance());
    }

    public DataExfilDetector(String name, ConfigManager config) {
        this(name,
                Boolean.parseBoolean(config.getString("detection.exfil.enabled", "false")),
                config.getInt("detection.exfil.windowSeconds", 300),
                config.getInt("detection.exfil.maxBytes", 5_000_000),
                config.getInt("detection.exfil.maxTracked", 2000),
                config.getInt("detection.exfil.cooldownSeconds", 600),
                config.getList("detection.exfil.allowlist"),
                config.getList("detection.exfil.internalPrefixes"));
    }

    DataExfilDetector(String name, boolean enabled, int windowSeconds, long maxBytes,
                      int maxTracked, int cooldownSeconds, List<String> internalPrefixes) {
        this(name, enabled, windowSeconds, maxBytes, maxTracked, cooldownSeconds, List.of(), internalPrefixes);
    }

    DataExfilDetector(String name, boolean enabled, int windowSeconds, long maxBytes,
                      int maxTracked, int cooldownSeconds, List<String> allowlist,
                      List<String> internalPrefixes) {
        super(name != null ? name : "DataExfilDetector");
        this.enabled = enabled;
        this.windowMillis = Math.max(1, windowSeconds) * 1000L;
        this.maxBytes = Math.max(1L, maxBytes);
        this.maxTracked = Math.max(16, maxTracked);
        this.cooldownMillis = Math.max(0, cooldownSeconds) * 1000L;
        this.allowlist = cleaned(allowlist);
        this.internalPrefixes = cleaned(internalPrefixes);
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
        if (!enabled || e == null || e.timestamp() == null || e.bytes() <= 0) {
            return Optional.empty();
        }
        if (isInternal(e.destIp())) {
            return Optional.empty();
        }
        if (listed(allowlist, e.destIp()) || listed(allowlist, e.sourceIp())) {
            return Optional.empty();
        }
        String key = e.sourceIp();
        Window window = windows.get(key);
        if (window == null) {
            if (windows.size() >= maxTracked) {
                evictOldest();
            }
            window = new Window();
            window.start = e.timestamp();
            windows.put(key, window);
        }
        if (Duration.between(window.start, e.timestamp()).toMillis() > windowMillis) {
            window.start = e.timestamp();
            window.bytes = 0L;
        }
        window.bytes += e.bytes();
        if (window.bytes <= maxBytes) {
            return Optional.empty();
        }
        if (window.lastAlert != null && Duration.between(window.lastAlert, e.timestamp()).toMillis() < cooldownMillis) {
            return Optional.empty();
        }
        window.lastAlert = e.timestamp();
        String description = "Outbound volume of " + window.bytes + " bytes from " + e.sourceIp()
                + " to external host " + e.destIp() + " within "
                + (windowMillis / 1000) + "s (limit " + maxBytes + ")";
        return Optional.of(alertFactory.create(
                Severity.HIGH,
                AttackType.DATA_TRANSFER,
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

    public synchronized int trackedSources() {
        return windows.size();
    }

    public boolean isEnabled() {
        return enabled;
    }

    boolean isInternal(String ip) {
        if (ip == null) {
            return false;
        }
        for (String prefix : internalPrefixes) {
            if (ip.startsWith(prefix)) {
                return true;
            }
        }
        return false;
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
