package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Drops repeat alerts and alerts below a floor.
 *
 * <p>Two detectors can describe the same fact: a port scan produces a signature
 * alert and a burst alert for one source within a second. Repeats of the same
 * (detector, attack type, source, target) inside
 * {@code alerts.dedupe.windowSeconds} collapse into the first one. A severity
 * floor drops the long tail an operator has said they do not want.</p>
 *
 * <p>Suppression is counted, never silent: {@link #stats()} reports how many
 * alerts were folded and how many fell below the floor, so the effect of turning
 * the gate on is measurable rather than a mystery.</p>
 */
public final class AlertQualityGate implements AlertGate {

    /** Counters plus the size of the dedupe table. */
    public record Stats(boolean dedupeEnabled, String minimumSeverity, long duplicates, long belowFloor, int tracked) {
    }

    private final boolean dedupeEnabled;
    private final long windowMillis;
    private final Severity minimumSeverity;
    private final int maxKeys;
    private final Map<String, Instant> lastSeen = new LinkedHashMap<>();
    private final AtomicLong duplicates = new AtomicLong();
    private final AtomicLong belowFloor = new AtomicLong();

    public AlertQualityGate() {
        this(ConfigManager.getInstance());
    }

    public AlertQualityGate(ConfigManager config) {
        this(
                Boolean.parseBoolean(config.getString("alerts.dedupe.enabled", "false")),
                config.getInt("alerts.dedupe.windowSeconds", 60),
                severity(config.getString("alerts.minSeverity", "LOW")),
                config.getInt("alerts.dedupe.maxKeys", 5000));
    }

    public AlertQualityGate(boolean dedupeEnabled, int windowSeconds, Severity minimumSeverity, int maxKeys) {
        this.dedupeEnabled = dedupeEnabled;
        this.windowMillis = Math.max(1, windowSeconds) * 1000L;
        this.minimumSeverity = minimumSeverity == null ? Severity.LOW : minimumSeverity;
        this.maxKeys = Math.max(16, maxKeys);
    }

    @Override
    public synchronized boolean allow(Alert alert) {
        if (alert == null) {
            return false;
        }
        if (rank(alert.getSeverity()) < rank(minimumSeverity)) {
            belowFloor.incrementAndGet();
            return false;
        }
        if (!dedupeEnabled) {
            return true;
        }
        String key = key(alert);
        Instant now = alert.getTimestamp();
        Instant last = lastSeen.get(key);
        if (last != null) {
            long age = Duration.between(last, now).toMillis();
            // A negative age means the alert is older than the one already seen
            // (out of order arrival); it is not a duplicate, so it is allowed
            // through and replaces the mark.
            if (age >= 0 && age < windowMillis) {
                duplicates.incrementAndGet();
                return false;
            }
        }
        lastSeen.put(key, now);
        prune(now);
        return true;
    }

    public synchronized Stats stats() {
        return new Stats(dedupeEnabled, minimumSeverity.name(), duplicates.get(), belowFloor.get(), lastSeen.size());
    }

    public synchronized void reset() {
        lastSeen.clear();
        duplicates.set(0L);
        belowFloor.set(0L);
    }

    public boolean isDedupeEnabled() {
        return dedupeEnabled;
    }

    public int getWindowSeconds() {
        return (int) (windowMillis / 1000);
    }

    public Severity getMinimumSeverity() {
        return minimumSeverity;
    }

    private void prune(Instant now) {
        // Entries older than the window can never suppress anything again, so
        // they are the first to go. The size cap is a second safety net: a
        // LinkedHashMap gives up its oldest insertion first.
        Iterator<Map.Entry<String, Instant>> iterator = lastSeen.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Instant> entry = iterator.next();
            if (Duration.between(entry.getValue(), now).toMillis() > windowMillis) {
                iterator.remove();
            }
        }
        while (lastSeen.size() > maxKeys) {
            Iterator<String> keys = lastSeen.keySet().iterator();
            keys.next();
            keys.remove();
        }
    }

    private static String key(Alert alert) {
        return alert.getDetectorName() + '|' + alert.getAttackType() + '|'
                + alert.getSourceIp() + '|' + alert.getTargetIp();
    }

    private static int rank(Severity severity) {
        if (severity == null) {
            return 0;
        }
        return switch (severity) {
            case LOW -> 1;
            case HIGH -> 2;
            case CRITICAL -> 3;
        };
    }

    private static Severity severity(String raw) {
        if (raw == null) {
            return Severity.LOW;
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            return Severity.LOW;
        }
    }
}
