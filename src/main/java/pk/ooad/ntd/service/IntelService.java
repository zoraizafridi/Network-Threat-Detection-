package pk.ooad.ntd.service;

import pk.ooad.ntd.detection.ThreatIntelDetector;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.intel.ThreatIntel;
import pk.ooad.ntd.util.ConfigManager;

import java.io.IOException;
import java.time.Instant;
import java.util.Locale;

public final class IntelService {

    private final ThreatIntelDetector detector;
    private final String feed;
    private final boolean enabled;
    private final Severity fallbackSeverity;
    private volatile Instant lastReloadAt;

    public IntelService(ThreatIntelDetector detector) {
        this(detector,
                ConfigManager.getInstance().getString("intel.feed", "threat-intel.json"),
                Boolean.parseBoolean(ConfigManager.getInstance().getString("intel.enabled", "false")),
                severity(ConfigManager.getInstance().getString("intel.defaultSeverity", "HIGH")));
    }

    IntelService(ThreatIntelDetector detector, String feed, boolean enabled, Severity fallbackSeverity) {
        this.detector = detector;
        this.feed = feed == null || feed.isBlank() ? "threat-intel.json" : feed.trim();
        this.enabled = enabled;
        this.fallbackSeverity = fallbackSeverity == null ? Severity.HIGH : fallbackSeverity;
    }

    public Status status() {
        return describe(detector == null ? ThreatIntel.empty(feed) : detector.feed());
    }

    public Status reload() throws IOException {
        ThreatIntel loaded = ThreatIntel.load(feed, fallbackSeverity);
        if (detector != null) {
            detector.reload(loaded);
        }
        lastReloadAt = Instant.now();
        return describe(loaded);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String feedPath() {
        return feed;
    }

    private Status describe(ThreatIntel loaded) {
        return new Status(enabled, feed, detector != null, loaded.size(), loaded.addressCount(),
                loaded.domainCount(), loaded.digestCount(), loaded.skippedLines(),
                loaded.expiredEntries(), loaded.source(), lastReloadAt);
    }

    private static Severity severity(String raw) {
        if (raw == null || raw.isBlank()) {
            return Severity.HIGH;
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return Severity.HIGH;
        }
    }

    public record Status(boolean enabled, String feed, boolean wired, int entries, int addresses,
                         int domains, int digests, long skipped, long expired, String source,
                         Instant lastReloadAt) {
    }
}
