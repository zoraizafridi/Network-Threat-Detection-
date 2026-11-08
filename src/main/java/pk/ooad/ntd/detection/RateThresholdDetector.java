package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class RateThresholdDetector extends Detector {
    private int windowSeconds;
    private int maxFailures;
    private final Map<String, Deque<Instant>> failuresBySource;

    public RateThresholdDetector(String name, int windowSeconds, int maxFailures) {
        super(name != null ? name : "RateThresholdDetector");
        this.windowSeconds = windowSeconds;
        this.maxFailures = maxFailures;
        this.failuresBySource = new ConcurrentHashMap<>();
    }

    public RateThresholdDetector() {
        this("RateThresholdDetector",
            ConfigManager.getInstance().getInt("detection.rate.windowSeconds", 60),
            ConfigManager.getInstance().getInt("detection.rate.maxFailures", 5));
    }

    @Override
    public synchronized Optional<Alert> analyze(NetworkEvent e) {
        if (e == null) {
            return Optional.empty();
        }

        if (e.type() == EventType.LOGIN_ATTEMPT && !e.success()) {
            Instant now = e.timestamp();
            Deque<Instant> q = failuresBySource.computeIfAbsent(e.sourceIp(), k -> new ArrayDeque<>());
            prune(q, now);
            q.addLast(now);

            if (q.size() > maxFailures) {
                Alert alert = alertFactory.create(
                    Severity.HIGH,
                    AttackType.BRUTE_FORCE,
                    e.sourceIp(),
                    e.destIp(),
                    getName(),
                    "Failed login threshold exceeded: " + q.size() + " failures within " + windowSeconds + "s",
                    now
                );
                return Optional.of(alert);
            }
        }

        return Optional.empty();
    }

    private void prune(Deque<Instant> q, Instant now) {
        if (now == null) {
            return;
        }
        Instant cutoff = now.minusSeconds(windowSeconds);
        while (!q.isEmpty() && q.peekFirst().isBefore(cutoff)) {
            q.pollFirst();
        }
    }

    @Override
    public synchronized void reset() {
        failuresBySource.clear();
    }

    public int getWindowSeconds() {
        return windowSeconds;
    }

    public void setWindowSeconds(int windowSeconds) {
        this.windowSeconds = windowSeconds;
    }

    public int getMaxFailures() {
        return maxFailures;
    }

    public void setMaxFailures(int maxFailures) {
        this.maxFailures = maxFailures;
    }

    public Map<String, Deque<Instant>> getFailuresBySource() {
        return Collections.unmodifiableMap(failuresBySource);
    }
}
