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

public final class ContainmentService implements AlertListener {

    public enum Mode {
        OFF, IDS, IPS
    }

    public record Action(String ip, Instant blockedAt, Instant expiresAt, String reason,
                         String actor, boolean automatic) {
        boolean activeAt(Instant now) {
            return now.isBefore(expiresAt);
        }
    }

    public record Status(Mode mode, boolean enabled, boolean auto, boolean enforce, Severity minSeverity,
                         int blocked, long droppedEvents, long automaticActions, long expiredActions,
                         long refusedActions) {
    }

    public interface Safeguard {
        String refusal(String ip);
    }

    public interface Recorder {
        void blocked(Action action, boolean automatic);

        void released(Action action);
    }

    private final Clock clock;
    private volatile Mode mode;
    private final boolean auto;
    private final int autoMinutes;
    private final int maxDurationMinutes;
    private final int maxBlocked;
    private final Severity autoSeverity;
    private final Severity minSeverity;
    private volatile Safeguard safeguard = ip -> null;
    private final Map<String, Action> blocked = new LinkedHashMap<>();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong automatic = new AtomicLong();
    private final AtomicLong expired = new AtomicLong();
    private final AtomicLong refused = new AtomicLong();
    private Recorder recorder = new Recorder() {
        @Override
        public void blocked(Action action, boolean automaticAction) {
        }

        @Override
        public void released(Action action) {
        }
    };

    public ContainmentService() {
        this(Clock.systemUTC(), ConfigManager.getInstance());
    }

    public ContainmentService(Clock clock, ConfigManager config) {
        this(clock,
                mode(config),
                Boolean.parseBoolean(config.getString("containment.auto", "false")),
                config.getInt("containment.autoMinutes", 30),
                config.getInt("containment.maxDurationMinutes", 1440),
                config.getInt("containment.maxBlocked", 500),
                severity(config.getString("containment.autoSeverity", "CRITICAL"), Severity.CRITICAL),
                severity(config.getString("containment.minSeverity", "LOW"), Severity.LOW));
    }

    ContainmentService(Clock clock, boolean enabled, boolean auto, boolean enforce,
                       int autoMinutes, int maxDurationMinutes, int maxBlocked,
                       Severity autoSeverity) {
        this(clock, enabled ? (enforce ? Mode.IPS : Mode.IDS) : Mode.OFF, auto, autoMinutes,
                maxDurationMinutes, maxBlocked, autoSeverity, Severity.LOW);
    }

    ContainmentService(Clock clock, Mode mode, boolean auto, int autoMinutes, int maxDurationMinutes,
                       int maxBlocked, Severity autoSeverity, Severity minSeverity) {
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
        this.mode = mode == null ? Mode.OFF : mode;
        this.auto = auto;
        this.autoMinutes = Math.max(1, autoMinutes);
        this.maxDurationMinutes = Math.max(1, maxDurationMinutes);
        this.maxBlocked = Math.max(16, maxBlocked);
        this.autoSeverity = autoSeverity == null ? Severity.CRITICAL : autoSeverity;
        this.minSeverity = minSeverity == null ? Severity.LOW : minSeverity;
    }

    static Mode mode(ConfigManager config) {
        Mode parsed = parseMode(config.getString("containment.mode", ""));
        if (parsed != null) {
            return parsed;
        }
        if (!Boolean.parseBoolean(config.getString("containment.enabled", "false"))) {
            return Mode.OFF;
        }
        return Boolean.parseBoolean(config.getString("containment.enforce", "false")) ? Mode.IPS : Mode.IDS;
    }

    public static Mode parseMode(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Mode.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    public Mode mode() {
        return mode;
    }

    public boolean enabled() {
        return mode != Mode.OFF;
    }

    public boolean enforcing() {
        return mode == Mode.IPS;
    }

    public void setSafeguard(Safeguard guard) {
        this.safeguard = guard == null ? ip -> null : guard;
    }

    public synchronized void setMode(Mode next) {
        Mode value = next == null ? Mode.OFF : next;
        if (value == mode) {
            return;
        }
        mode = value;
        EventLog.getInstance().log(LogLevel.INFO, "containment",
                "Mode changed to " + value + (value == Mode.IPS
                        ? "; traffic from contained sources is dropped"
                        : value == Mode.IDS ? "; traffic keeps flowing" : "; nothing is recorded"));
    }

    public boolean admit(NetworkEvent event) {
        if (mode != Mode.IPS || event == null || event.sourceIp() == null) {
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
        if (mode == Mode.OFF) {
            throw new IllegalStateException("containment is disabled");
        }
        String address = ip == null ? "" : ip.trim();
        if (address.isEmpty()) {
            throw new IllegalArgumentException("ip must not be blank");
        }
        String obstacle = safeguard.refusal(address);
        if (obstacle != null) {
            refused.incrementAndGet();
            throw new IllegalStateException("refused: " + obstacle);
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
        recorder.blocked(action, false);
        return action;
    }

    public boolean release(String ip) {
        if (ip == null) {
            return false;
        }
        Action removed;
        synchronized (this) {
            removed = blocked.remove(ip.trim());
        }
        if (removed != null) {
            recorder.released(removed);
        }
        return removed != null;
    }

    public void setRecorder(Recorder sink) {
        this.recorder = sink == null ? this.recorder : sink;
    }

    public synchronized boolean restore(Action action) {
        if (action == null || action.ip() == null || !action.activeAt(clock.instant())) {
            return false;
        }
        if (blocked.size() >= maxBlocked && !blocked.containsKey(action.ip())) {
            return false;
        }
        blocked.put(action.ip(), action);
        if (action.automatic()) {
            automatic.incrementAndGet();
        }
        return true;
    }

    public synchronized boolean isBlocked(String ip) {
        if (ip == null) {
            return false;
        }
        Action action = blocked.get(ip.trim());
        return action != null && action.activeAt(clock.instant());
    }

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
        if (mode == Mode.OFF || !auto || alert == null
                || alert.getSourceIp() == null || alert.getSourceIp().isBlank()) {
            return;
        }
        Severity floor = minSeverity.compareTo(autoSeverity) > 0 ? minSeverity : autoSeverity;
        if (alert.getSeverity().compareTo(floor) < 0) {
            return;
        }
        Action action = null;
        synchronized (this) {
            Action existing = blocked.get(alert.getSourceIp());
            if (existing != null && existing.activeAt(clock.instant())) {
                return;
            }
            if (blocked.size() >= maxBlocked) {
                return;
            }
            if (safeguard.refusal(alert.getSourceIp()) != null) {
                refused.incrementAndGet();
                return;
            }
            Instant now = clock.instant();
            action = new Action(alert.getSourceIp(), now,
                    now.plus(Duration.ofMinutes(Math.min(autoMinutes, maxDurationMinutes))),
                    "auto: " + alert.getDetectorName() + " raised " + alert.getSeverity(),
                    "system", true);
            blocked.put(alert.getSourceIp(), action);
            automatic.incrementAndGet();
        }
        recorder.blocked(action, true);
    }

    public synchronized Status status() {
        int active = 0;
        Instant now = clock.instant();
        for (Action action : blocked.values()) {
            if (action.activeAt(now)) {
                active++;
            }
        }
        return new Status(mode, enabled(), auto, enforcing(), minSeverity, active, dropped.get(),
                automatic.get(), expired.get(), refused.get());
    }

    public synchronized void reset() {
        blocked.clear();
        dropped.set(0);
        automatic.set(0);
        expired.set(0);
        refused.set(0);
    }

    private static Severity severity(String raw, Severity fallback) {
        if (raw == null) {
            return fallback;
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return fallback;
        }
    }
}
