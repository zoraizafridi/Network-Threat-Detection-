package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class PortScanDetector extends Detector {
    private int windowSeconds;
    private int maxDistinctPorts;
    private int maxDistinctHosts;
    private final Map<String, Deque<Touch>> touches;

    public static record Touch(Instant time, int port, String host) {}

    public PortScanDetector(String name, int windowSeconds, int maxDistinctPorts, int maxDistinctHosts) {
        super(name != null ? name : "PortScanDetector");
        this.windowSeconds = windowSeconds;
        this.maxDistinctPorts = maxDistinctPorts;
        this.maxDistinctHosts = maxDistinctHosts;
        this.touches = new ConcurrentHashMap<>();
    }

    public PortScanDetector() {
        this("PortScanDetector",
            ConfigManager.getInstance().getInt("detection.portScan.windowSeconds", 60),
            ConfigManager.getInstance().getInt("detection.portScan.maxDistinctPorts", 10),
            ConfigManager.getInstance().getInt("detection.portScan.maxDistinctHosts", 15));
    }

    @Override
    public synchronized Optional<Alert> analyze(NetworkEvent e) {
        if (e == null) {
            return Optional.empty();
        }

        Instant now = e.timestamp();
        Deque<Touch> q = touches.computeIfAbsent(e.sourceIp(), k -> new ArrayDeque<>());

        Instant cutoff = now.minusSeconds(windowSeconds);
        while (!q.isEmpty() && q.peekFirst().time().isBefore(cutoff)) {
            q.pollFirst();
        }

        q.addLast(new Touch(now, e.port(), e.destIp()));

        Set<Integer> distinctPorts = new HashSet<>();
        Set<String> distinctHosts = new HashSet<>();
        for (Touch t : q) {
            distinctPorts.add(t.port());
            distinctHosts.add(t.host());
        }

        if (distinctPorts.size() > maxDistinctPorts || distinctHosts.size() > maxDistinctHosts) {
            Alert alert = alertFactory.create(
                Severity.HIGH,
                AttackType.PORT_SCAN,
                e.sourceIp(),
                e.destIp(),
                getName(),
                "Port scan detected: " + distinctPorts.size() + " ports, " + distinctHosts.size() + " hosts",
                now
            );
            return Optional.of(alert);
        }

        return Optional.empty();
    }

    @Override
    public synchronized void reset() {
        touches.clear();
    }

    public int getWindowSeconds() {
        return windowSeconds;
    }

    public void setWindowSeconds(int windowSeconds) {
        this.windowSeconds = windowSeconds;
    }

    public int getMaxDistinctPorts() {
        return maxDistinctPorts;
    }

    public void setMaxDistinctPorts(int maxDistinctPorts) {
        this.maxDistinctPorts = maxDistinctPorts;
    }

    public int getMaxDistinctHosts() {
        return maxDistinctHosts;
    }

    public void setMaxDistinctHosts(int maxDistinctHosts) {
        this.maxDistinctHosts = maxDistinctHosts;
    }

    public Map<String, Deque<Touch>> getTouches() {
        return Collections.unmodifiableMap(touches);
    }
}
