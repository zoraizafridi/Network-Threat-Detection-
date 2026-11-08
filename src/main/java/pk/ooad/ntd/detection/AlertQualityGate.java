package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public final class AlertQualityGate implements AlertGate {

    public record Stats(boolean dedupeEnabled, String minimumSeverity, long delivered, long duplicates,
                        long belowFloor, long ruleSuppressed, long stormSuppressed, int tracked,
                        int maxPerMinute, int rules) {
    }

    private static final int PRUNE_BUDGET = 16;

    private final boolean dedupeEnabled;
    private final long windowMillis;
    private final Severity minimumSeverity;
    private final int maxKeys;
    private final int maxPerMinute;
    private final SuppressionRules rules;
    private final Map<String, Alert> lastSeen = new LinkedHashMap<>();
    private final Deque<Long> deliveries = new ArrayDeque<>();
    private final AtomicLong delivered = new AtomicLong();
    private final AtomicLong duplicates = new AtomicLong();
    private final AtomicLong belowFloor = new AtomicLong();
    private final AtomicLong ruleSuppressed = new AtomicLong();
    private final AtomicLong stormSuppressed = new AtomicLong();

    public AlertQualityGate() {
        this(ConfigManager.getInstance());
    }

    public AlertQualityGate(ConfigManager config) {
        this(config, new SuppressionRules(config));
    }

    public AlertQualityGate(ConfigManager config, SuppressionRules rules) {
        this(
                Boolean.parseBoolean(config.getString("alerts.dedupe.enabled", "true")),
                config.getInt("alerts.dedupe.windowSeconds", 60),
                severity(config.getString("alerts.minSeverity", "LOW")),
                config.getInt("alerts.dedupe.maxKeys", 5000),
                config.getInt("alerts.maxPerMinute", 600),
                rules);
    }

    public AlertQualityGate(boolean dedupeEnabled, int windowSeconds, Severity minimumSeverity, int maxKeys) {
        this(dedupeEnabled, windowSeconds, minimumSeverity, maxKeys, 0, null);
    }

    public AlertQualityGate(boolean dedupeEnabled, int windowSeconds, Severity minimumSeverity, int maxKeys,
                            int maxPerMinute, SuppressionRules rules) {
        this.dedupeEnabled = dedupeEnabled;
        this.windowMillis = Math.max(1, windowSeconds) * 1000L;
        this.minimumSeverity = minimumSeverity == null ? Severity.LOW : minimumSeverity;
        this.maxKeys = Math.max(16, maxKeys);
        this.maxPerMinute = Math.max(0, maxPerMinute);
        this.rules = rules;
    }

    @Override
    public boolean allow(Alert alert) {
        return decide(alert).isDelivered();
    }

    @Override
    public synchronized Decision decide(Alert alert) {
        if (alert == null) {
            return Decision.suppress("empty");
        }
        Instant now = alert.getTimestamp();
        if (rank(alert.getSeverity()) < rank(minimumSeverity)) {
            belowFloor.incrementAndGet();
            return Decision.suppress("floor");
        }
        String rule = rules == null ? null : rules.match(alert);
        if (rule != null) {
            ruleSuppressed.incrementAndGet();
            return Decision.suppress("rule:" + rule);
        }
        String key = dedupeEnabled ? key(alert) : null;
        if (key != null) {
            Alert previous = lastSeen.get(key);
            if (previous != null) {
                Instant last = previous.getLastSeen() != null ? previous.getLastSeen() : previous.getTimestamp();
                long age = Duration.between(last, now).toMillis();
                if (age >= 0 && age < windowMillis) {
                    duplicates.incrementAndGet();
                    return Decision.fold(previous);
                }
            }
        }
        if (overStormCap(now)) {
            stormSuppressed.incrementAndGet();
            return Decision.suppress("storm");
        }
        if (key != null) {
            lastSeen.put(key, alert);
            prune(now);
        }
        delivered.incrementAndGet();
        deliveries.addLast(now.toEpochMilli());
        return Decision.deliver();
    }

    public synchronized Stats stats() {
        return new Stats(dedupeEnabled, minimumSeverity.name(), delivered.get(), duplicates.get(),
                belowFloor.get(), ruleSuppressed.get(), stormSuppressed.get(), lastSeen.size(),
                maxPerMinute, rules == null ? 0 : rules.rules().size());
    }

    public synchronized void reset() {
        lastSeen.clear();
        deliveries.clear();
        delivered.set(0L);
        duplicates.set(0L);
        belowFloor.set(0L);
        ruleSuppressed.set(0L);
        stormSuppressed.set(0L);
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

    public int getMaxPerMinute() {
        return maxPerMinute;
    }

    public SuppressionRules getRules() {
        return rules;
    }

    private boolean overStormCap(Instant now) {
        if (maxPerMinute <= 0) {
            return false;
        }
        long cutoff = now.toEpochMilli() - 60_000L;
        while (!deliveries.isEmpty() && deliveries.peekFirst() < cutoff) {
            deliveries.removeFirst();
        }
        return deliveries.size() >= maxPerMinute;
    }

    private void prune(Instant now) {
        long cutoff = now.toEpochMilli() - windowMillis;
        int budget = PRUNE_BUDGET;
        Iterator<Map.Entry<String, Alert>> iterator = lastSeen.entrySet().iterator();
        while (iterator.hasNext() && budget-- > 0) {
            Map.Entry<String, Alert> entry = iterator.next();
            Instant last = entry.getValue().getLastSeen();
            if (last != null && last.toEpochMilli() < cutoff) {
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
