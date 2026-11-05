package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class DetectionEngine {
    private final BlockingQueue<NetworkEvent> queue;
    private final AlertBus alertBus;
    private final List<Detector> detectors;
    private Thread worker;
    private final AtomicBoolean running;
    private int cooldownSeconds;
    private final Map<String, Instant> lastAlertAt;

    public DetectionEngine(BlockingQueue<NetworkEvent> queue, AlertBus alertBus, int cooldownSeconds) {
        this.queue = Objects.requireNonNull(queue, "queue must not be null");
        this.alertBus = Objects.requireNonNull(alertBus, "alertBus must not be null");
        this.cooldownSeconds = cooldownSeconds;
        this.detectors = new CopyOnWriteArrayList<>();
        this.running = new AtomicBoolean(false);
        this.lastAlertAt = new ConcurrentHashMap<>();
    }

    public DetectionEngine(BlockingQueue<NetworkEvent> queue, AlertBus alertBus) {
        this(queue, alertBus, 5);
    }

    public synchronized void start() {
        if (running.compareAndSet(false, true)) {
            worker = new Thread(this::runLoop, "DetectionEngine-Worker");
            worker.setDaemon(true);
            worker.start();
        }
    }

    public synchronized void stop() {
        running.set(false);
        if (worker != null) {
            worker.interrupt();
            try {
                worker.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            worker = null;
        }
    }

    public synchronized void reset() {
        for (Detector d : detectors) {
            d.reset();
        }
        lastAlertAt.clear();
    }

    public void addDetector(Detector d) {
        if (d != null) {
            detectors.add(d);
        }
    }

    private void runLoop() {
        while (running.get()) {
            try {
                NetworkEvent event = queue.poll(50, TimeUnit.MILLISECONDS);
                if (event != null) {
                    process(event);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void process(NetworkEvent e) {
        for (Detector detector : detectors) {
            Optional<Alert> optAlert = detector.analyze(e);
            if (optAlert.isPresent()) {
                Alert alert = optAlert.get();
                String source = alert.getSourceIp();
                Instant now = alert.getTimestamp();

                // Apply per-source cooldown using lastAlertAt
                Instant lastTime = lastAlertAt.get(source);
                if (lastTime != null && cooldownSeconds > 0) {
                    Instant cooldownExpires = lastTime.plusSeconds(cooldownSeconds);
                    if (now.isBefore(cooldownExpires) || now.equals(lastTime)) {
                        // Suppressed by per-source cooldown
                        continue;
                    }
                }

                lastAlertAt.put(source, now);
                alertBus.publish(alert);
            }
        }
    }

    public BlockingQueue<NetworkEvent> getQueue() {
        return queue;
    }

    public AlertBus getAlertBus() {
        return alertBus;
    }

    public List<Detector> getDetectors() {
        return Collections.unmodifiableList(detectors);
    }

    public int getCooldownSeconds() {
        return cooldownSeconds;
    }

    public void setCooldownSeconds(int cooldownSeconds) {
        this.cooldownSeconds = cooldownSeconds;
    }

    public Map<String, Instant> getLastAlertAt() {
        return Collections.unmodifiableMap(lastAlertAt);
    }

    public boolean isRunning() {
        return running.get();
    }
}

