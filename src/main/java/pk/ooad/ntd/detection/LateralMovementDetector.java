package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Flags one source reaching many different hosts inside a short window.
 *
 * <p>This is the east-west pattern: a single workstation touching a handful of
 * servers is normal, but one workstation touching host after host on management
 * ports is how an intruder looks for the next hop. Administrative ports are
 * counted separately from the rest so the alert can say which of the two
 * thresholds fired.</p>
 *
 * <p>Visits live in a deque per source and are pruned on every event, so the
 * memory per source is bounded by the number of hosts seen inside one window.</p>
 */
public class LateralMovementDetector extends Detector {

    private record Visit(Instant at, String host, int port) {
    }

    private static final class Source {
        private final Deque<Visit> visits = new ArrayDeque<>();
        private Instant lastAlert;
    }

    private final boolean enabled;
    private final long windowMillis;
    private final int maxHosts;
    private final int maxTracked;
    private final long cooldownMillis;
    private final Set<Integer> adminPorts;
    private final Map<String, Source> sources = new HashMap<>();

    public LateralMovementDetector() {
        this("LateralMovementDetector", ConfigManager.getInstance());
    }

    public LateralMovementDetector(String name, ConfigManager config) {
        this(name,
                Boolean.parseBoolean(config.getString("detection.lateral.enabled", "false")),
                config.getInt("detection.lateral.windowSeconds", 120),
                config.getInt("detection.lateral.maxHosts", 4),
                config.getInt("detection.lateral.maxTracked", 1000),
                config.getInt("detection.lateral.cooldownSeconds", 300),
                ports(config.getList("detection.lateral.adminPorts")));
    }

    LateralMovementDetector(String name, boolean enabled, int windowSeconds, int maxHosts,
                            int maxTracked, int cooldownSeconds, Set<Integer> adminPorts) {
        super(name != null ? name : "LateralMovementDetector");
        this.enabled = enabled;
        this.windowMillis = Math.max(1, windowSeconds) * 1000L;
        this.maxHosts = Math.max(2, maxHosts);
        this.maxTracked = Math.max(16, maxTracked);
        this.cooldownMillis = Math.max(0, cooldownSeconds) * 1000L;
        this.adminPorts = adminPorts == null ? Set.of() : Set.copyOf(adminPorts);
    }

    @Override
    public synchronized Optional<Alert> analyze(NetworkEvent e) {
        if (!enabled || e == null || e.timestamp() == null || e.destIp() == null) {
            return Optional.empty();
        }
        String key = e.sourceIp();
        Source source = sources.get(key);
        if (source == null) {
            if (sources.size() >= maxTracked) {
                evictOldest();
            }
            source = new Source();
            sources.put(key, source);
        }
        Instant cutoff = e.timestamp().minusMillis(windowMillis);
        while (!source.visits.isEmpty() && source.visits.peekFirst().at().isBefore(cutoff)) {
            source.visits.pollFirst();
        }
        source.visits.addLast(new Visit(e.timestamp(), e.destIp(), e.port()));
        // A repeated host adds nothing to distinctness, so the deque never needs
        // to be longer than a small multiple of the threshold.
        while (source.visits.size() > maxHosts * 8) {
            source.visits.pollFirst();
        }

        Set<String> hosts = new HashSet<>();
        Set<Integer> admin = new HashSet<>();
        for (Visit visit : source.visits) {
            hosts.add(visit.host());
            if (adminPorts.contains(visit.port())) {
                admin.add(visit.port());
            }
        }
        if (hosts.size() < maxHosts) {
            return Optional.empty();
        }
        if (source.lastAlert != null && Duration.between(source.lastAlert, e.timestamp()).toMillis() < cooldownMillis) {
            return Optional.empty();
        }
        source.lastAlert = e.timestamp();
        List<Integer> ports = new ArrayList<>(admin);
        ports.sort(Integer::compareTo);
        String description = "Lateral movement: " + e.sourceIp() + " reached " + hosts.size()
                + " hosts within " + (windowMillis / 1000) + "s"
                + (ports.isEmpty() ? "" : " including management ports " + ports);
        return Optional.of(alertFactory.create(
                Severity.HIGH,
                AttackType.PORT_SCAN,
                e.sourceIp(),
                e.destIp(),
                getName(),
                description,
                e.timestamp()));
    }

    @Override
    public synchronized void reset() {
        sources.clear();
    }

    public synchronized int trackedSources() {
        return sources.size();
    }

    public boolean isEnabled() {
        return enabled;
    }

    private void evictOldest() {
        String oldestKey = null;
        Instant oldest = null;
        for (Map.Entry<String, Source> entry : sources.entrySet()) {
            Visit first = entry.getValue().visits.peekFirst();
            Instant at = first == null ? null : first.at();
            if (at != null && (oldest == null || at.isBefore(oldest))) {
                oldest = at;
                oldestKey = entry.getKey();
            }
        }
        if (oldestKey != null) {
            sources.remove(oldestKey);
        } else {
            sources.clear();
        }
    }

    private static Set<Integer> ports(List<String> raw) {
        Set<Integer> ports = new HashSet<>();
        if (raw != null) {
            for (String item : raw) {
                try {
                    int port = Integer.parseInt(item.trim());
                    if (port > 0 && port <= 65_535) {
                        ports.add(port);
                    }
                } catch (NumberFormatException ignored) {
                    // A malformed entry simply drops out of the admin set.
                }
            }
        }
        return ports;
    }
}
