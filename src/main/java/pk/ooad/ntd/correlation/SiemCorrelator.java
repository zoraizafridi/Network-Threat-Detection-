package pk.ooad.ntd.correlation;

import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class SiemCorrelator implements AlertListener {

    public static final String DETECTOR_NAME = "SiemCorrelator";

    public record Status(boolean enabled, int trackedSources, long signals,
                         long correlated, int minSignals, int windowSeconds,
                         int chains, long chainsMatched, String lastChain, String chainProblem) {
    }

    private record Signal(Instant at, AttackType type, String targetIp) {
    }

    private record ChainProgress(int stage, Instant startedAt) {
    }

    private static final class Window {
        private final Deque<Signal> signals = new ArrayDeque<>();
        private final Map<String, ChainProgress> chains = new HashMap<>();
        private Instant lastAlert;
    }

    private final AlertBus alertBus;
    private final AlertFactory alertFactory = new AlertFactory();
    private final boolean enabled;
    private final int minSignals;
    private final int windowSeconds;
    private final int cooldownSeconds;
    private final int maxSources;
    private final Severity escalateSeverity;
    private final KillChainRules chains;
    private final Map<String, Window> windows = new HashMap<>();
    private long signalCount;
    private long correlatedCount;
    private long chainsMatched;
    private String lastChain = "";

    public SiemCorrelator(AlertBus alertBus) {
        this(alertBus, ConfigManager.getInstance());
    }

    public SiemCorrelator(AlertBus alertBus, ConfigManager config) {
        this(alertBus,
                Boolean.parseBoolean(config.getString("correlation.enabled", "false")),
                config.getInt("correlation.minSignals", 2),
                config.getInt("correlation.windowSeconds", 600),
                config.getInt("correlation.cooldownSeconds", 600),
                config.getInt("correlation.maxSources", 2000),
                severity(config.getString("correlation.escalateSeverity", "HIGH")),
                new KillChainRules(config));
    }

    SiemCorrelator(AlertBus alertBus, boolean enabled, int minSignals, int windowSeconds,
                   int cooldownSeconds, int maxSources, Severity escalateSeverity) {
        this(alertBus, enabled, minSignals, windowSeconds, cooldownSeconds, maxSources,
                escalateSeverity, new KillChainRules(List.of(), null));
    }

    SiemCorrelator(AlertBus alertBus, boolean enabled, int minSignals, int windowSeconds,
                   int cooldownSeconds, int maxSources, Severity escalateSeverity,
                   KillChainRules chains) {
        this.alertBus = Objects.requireNonNull(alertBus, "alertBus must not be null");
        this.enabled = enabled;
        this.minSignals = Math.max(2, minSignals);
        this.windowSeconds = Math.max(1, windowSeconds);
        this.cooldownSeconds = Math.max(0, cooldownSeconds);
        this.maxSources = Math.max(16, maxSources);
        this.escalateSeverity = escalateSeverity == null ? Severity.HIGH : escalateSeverity;
        this.chains = chains == null ? new KillChainRules(List.of(), null) : chains;
    }

    @Override
    public synchronized void onAlert(Alert alert) {
        if (!enabled || alert == null || DETECTOR_NAME.equals(alert.getDetectorName())) {
            return;
        }
        String source = alert.getSourceIp();
        if (source == null || source.isBlank() || alert.getTimestamp() == null) {
            return;
        }
        Window window = windows.get(source);
        if (window == null) {
            if (windows.size() >= maxSources) {
                evictOldest();
            }
            window = new Window();
            windows.put(source, window);
        }
        Instant at = alert.getTimestamp();
        window.signals.addLast(new Signal(at, alert.getAttackType(), alert.getTargetIp()));
        prune(window, at);
        signalCount++;

        boolean cooled = window.lastAlert != null
                && Duration.between(window.lastAlert, at).getSeconds() < cooldownSeconds;
        KillChainRules.Chain completed = advanceChains(window, alert.getAttackType(), at);
        if (completed != null && !cooled) {
            window.lastAlert = at;
            correlatedCount++;
            chainsMatched++;
            lastChain = completed.name();
            alertBus.publish(alertFactory.create(completed.severity(), alert.getAttackType(), source,
                    alert.getTargetIp(), DETECTOR_NAME,
                    describeChain(completed, source, alert.getTargetIp()), at)
                    .markSimulated(alert.isSimulated()));
            return;
        }

        Set<AttackType> types = new LinkedHashSet<>();
        Set<String> targets = new LinkedHashSet<>();
        for (Signal signal : window.signals) {
            types.add(signal.type());
            if (signal.targetIp() != null && !signal.targetIp().isBlank()) {
                targets.add(signal.targetIp());
            }
        }
        if (types.size() < minSignals) {
            return;
        }
        if (cooled) {
            return;
        }
        window.lastAlert = at;
        correlatedCount++;

        AttackType newest = window.signals.peekLast().type();
        Alert correlated = alertFactory.create(escalateSeverity, newest, source,
                targets.isEmpty() ? alert.getTargetIp() : targets.iterator().next(),
                DETECTOR_NAME, describe(source, types, targets),
                at).markSimulated(alert.isSimulated());
        alertBus.publish(correlated);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public synchronized Status status() {
        return new Status(enabled, windows.size(), signalCount, correlatedCount,
                minSignals, windowSeconds, chains.size(), chainsMatched, lastChain,
                chains.problem());
    }

    public synchronized void reset() {
        windows.clear();
        signalCount = 0;
        correlatedCount = 0;
        chainsMatched = 0;
        lastChain = "";
    }

    private KillChainRules.Chain advanceChains(Window window, AttackType type, Instant at) {
        KillChainRules.Chain completed = null;
        for (KillChainRules.Chain chain : chains.rules()) {
            ChainProgress progress = window.chains.get(chain.id());
            if (progress != null
                    && Duration.between(progress.startedAt(), at).getSeconds() > chain.windowSeconds()) {
                window.chains.remove(chain.id());
                progress = null;
            }
            if (progress == null) {
                if (chain.stages().get(0) == type) {
                    window.chains.put(chain.id(), new ChainProgress(1, at));
                }
                continue;
            }
            if (chain.stages().get(progress.stage()) != type) {
                continue;
            }
            int next = progress.stage() + 1;
            if (next >= chain.stages().size()) {
                window.chains.remove(chain.id());
                if (completed == null) {
                    completed = chain;
                }
            } else {
                window.chains.put(chain.id(), new ChainProgress(next, progress.startedAt()));
            }
        }
        return completed;
    }

    private void prune(Window window, Instant newest) {
        Instant oldest = newest.minusSeconds(windowSeconds);
        while (!window.signals.isEmpty() && window.signals.peekFirst().at().isBefore(oldest)) {
            window.signals.removeFirst();
        }
    }

    private void evictOldest() {
        String oldestKey = null;
        Instant oldest = null;
        for (Map.Entry<String, Window> entry : windows.entrySet()) {
            Signal first = entry.getValue().signals.peekFirst();
            Instant start = first == null ? null : first.at();
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

    private String describeChain(KillChainRules.Chain chain, String source, String targetIp) {
        return "Possible compromise: " + chain.name() + " from " + source
                + " (" + chain.path() + ") within " + chain.windowSeconds() + "s against "
                + (targetIp == null || targetIp.isBlank() ? "the network" : targetIp);
    }

    private String describe(String source, Set<AttackType> types, Set<String> targets) {
        List<String> names = new ArrayList<>();
        for (AttackType type : types) {
            names.add(type.name());
        }
        List<String> hosts = new ArrayList<>(targets);
        if (hosts.size() > 4) {
            hosts = hosts.subList(0, 4);
        }
        return "Source " + source + " raised " + types.size() + " distinct attack types ("
                + String.join(", ", names) + ") against " + targets.size()
                + " host(s) " + hosts + " within " + windowSeconds + "s";
    }

    private static Severity severity(String raw) {
        if (raw == null) {
            return Severity.HIGH;
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return Severity.HIGH;
        }
    }
}
