package pk.ooad.ntd.containment;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A time-limited block list for source addresses, with two ways in: an operator
 * asking for one, or a rule that blocks a source when its alerts are severe
 * enough.
 *
 * <p>Manual containment is the reason the class exists; automatic containment
 * is off unless enabled, because a system that silently drops traffic on its
 * own is a system whose outages are hard to explain. Every action records who
 * asked for it, why, and when it lapses, and every action expires: an
 * indefinite block created during an incident becomes tomorrow's mystery.</p>
 *
 * <p>Enforcement is separate from record keeping. With enforcement off, actions
 * are logged and visible but traffic keeps flowing, which lets an operator
 * rehearse a response without changing what the network does.</p>
 */
public final class ContainmentService implements AlertListener {

    public record Action(String ip, Instant blockedAt, Instant expiresAt, String reason,
                         String actor, boolean automatic) {
        boolean activeAt(Instant now) {
            return now.isBefore(expiresAt);
        }
    }

    public record Status(boolean enabled, boolean auto, boolean enforce, int blocked,
                         long droppedEvents, long automaticActions, long expiredActions) {
    }

    private final Clock clock;
    private final boolean enabled;
    private final boolean auto;
    private final boolean enforce;
    private final int autoMinutes;
    private final int maxDurationMinutes;
    private final int maxBlocked;
    private final Severity autoSeverity;
    private final Map<String, Action> blocked = new LinkedHashMap<>();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong automatic = new AtomicLong();
    private final AtomicLong expired = new AtomicLong();

    public ContainmentService() {
        this(Clock.systemUTC(), ConfigManager.getInstance());
    }

    public ContainmentService(Clock clock, ConfigManager config) {
        this(clock,
                Boolean.parseBoolean(config.getString("containment.enabled", "false")),
                Boolean.parseBoolean(config.getString("containment.auto", "false")),
                Boolean.parseBoolean(config.getString("containment.enforce", "false")),
                config.getInt("containment.autoMinutes", 30),
                config.getInt("containment.maxDurationMinutes", 1440),
                config.getInt("containment.maxBlocked", 500),
                severity(config.getString("containment.autoSeverity", "CRITICAL")));
    }

    ContainmentService(Clock clock, boolean enabled, boolean auto, boolean enforce,
                       int autoMinutes, int maxDurationMinutes, int maxBlocked,
                       Severity autoSeverity) {
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
        this.enabled = enabled;
        this.auto = auto;
        this.enforce = enforce;
        this.autoMinutes = Math.max(1, autoMinutes);
        this.maxDurationMinutes = Math.max(1, maxDurationMinutes);
        this.maxBlocked = Math.max(16, maxBlocked);
        this.autoSeverity = autoSeverity == null ? Severity.CRITICAL : autoSeverity;
    }

    /**
     * Admission check called before detection. Only a blocked source is refused,
     * and only when enforcement is on, so the default path is unchanged.
     */
    public boolean admit(NetworkEvent event) {
        if (!enabled || !enforce || event == null || event.sourceIp() == null) {
            return true;
        }
        Instant now = clock.instant();
        synchronized (this) {
            Action action = blocked.get(event.sourceIp());
            if (action == null) {
                return true;
            }
            if (!action.activeAt(now)) {
                blocked.remove(event.sourceIp());
                expired.incrementAndGet();
                return true;
            }
            dropped.incrementAndGet();
            return false;
        }
    }

    public Action contain(String ip, int minutes, String reason, String actor) {
        if (!enabled) {
            throw new IllegalStateException("containment is disabled");
        }
        String address = ip == null ? "" : ip.trim();
        if (address.isEmpty()) {
            throw new IllegalArgumentException("ip must not be blank");
        }
        int duration = Math.min(maxDurationMinutes, Math.max(1, minutes));
        Instant now = clock.instant();
        Action action = new Action(address, now, now.plus(Duration.ofMinutes(duration)),
                reason == null ? "" : reason, actor == null ? "" : actor, false);
        synchronized (this) {
            if (blocked.size() >= maxBlocked && !blocked.containsKey(address)) {
                throw new IllegalStateException("containment list is full");
            }
            blocked.put(address, action);
        }
        EventLog.getInstance().log(LogLevel.WARN, "containment",
                "Blocked " + address + " for " + duration + " minutes by "
                        + (actor == null || actor.isBlank() ? "unknown" : actor) + ": " + action.reason());
        return action;
    }

    public boolean release(String ip) {
        if (ip == null) {
            return false;
        }
        synchronized (this) {
            return blocked.remove(ip.trim()) != null;
        }
    }

    public synchronized boolean isBlocked(String ip) {
        if (ip == null) {
            return false;
        }
        Action action = blocked.get(ip.trim());
        return action != null && action.activeAt(clock.instant());
    }

    /** Active actions, newest first. Expired rows are pruned as a side effect. */
    public synchronized List<Action> active() {
        Instant now = clock.instant();
        List<Action> result = new ArrayList<>();
        for (Action action : new ArrayList<>(blocked.values())) {
            if (action.activeAt(now)) {
                result.add(action);
            } else {
                blocked.remove(action.ip());
                expired.incrementAndGet();
            }
        }
        result.sort(Comparator.comparing(Action::blockedAt).reversed());
        return result;
    }

    @Override
    public void onAlert(Alert alert) {
        if (!enabled || !auto || alert == null || alert.getSourceIp() == null || alert.getSourceIp().isBlank()) {
            return;
        }
        if (alert.getSeverity().compareTo(autoSeverity) < 0) {
            return;
        }
        synchronized (this) {
            Action existing = blocked.get(alert.getSourceIp());
            if (existing != null && existing.activeAt(clock.instant())) {
                return;
            }
            if (blocked.size() >= maxBlocked) {
                return;
            }
            Instant now = clock.instant();
            blocked.put(alert.getSourceIp(), new Action(alert.getSourceIp(), now,
                    now.plus(Duration.ofMinutes(Math.min(autoMinutes, maxDurationMinutes))),
                    "auto: " + alert.getDetectorName() + " raised " + alert.getSeverity(),
                    "system", true));
            automatic.incrementAndGet();
        }
    }

    public synchronized Status status() {
        int active = 0;
        Instant now = clock.instant();
        for (Action action : blocked.values()) {
            if (action.activeAt(now)) {
                active++;
            }
        }
        return new Status(enabled, auto, enforce, active, dropped.get(), automatic.get(), expired.get());
    }

    public synchronized void reset() {
        blocked.clear();
        dropped.set(0);
        automatic.set(0);
        expired.set(0);
    }

    private static Severity severity(String raw) {
        if (raw == null) {
            return Severity.CRITICAL;
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return Severity.CRITICAL;
        }
    }
}
