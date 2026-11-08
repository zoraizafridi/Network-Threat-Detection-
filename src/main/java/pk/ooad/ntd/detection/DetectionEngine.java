package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

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
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Predicate;

public class DetectionEngine {
    private final BlockingQueue<NetworkEvent> queue;
    private final AlertBus alertBus;
    private final List<Detector> detectors;
    private Thread worker;
    private final AtomicBoolean running;
    private int cooldownSeconds;
    private final Map<String, Instant> lastAlertAt;
    private final List<Consumer<NetworkEvent>> eventObservers;
    private final AtomicBoolean observerFaultLogged = new AtomicBoolean(false);
    private volatile AlertGate alertGate = AlertGate.ALLOW_ALL;
    private volatile Predicate<NetworkEvent> admission = event -> true;
    private final AtomicLong droppedEvents = new AtomicLong();
    private final long queuePollMillis;
    private final long workerJoinMillis;

    public DetectionEngine(BlockingQueue<NetworkEvent> queue, AlertBus alertBus, int cooldownSeconds) {
        this.queue = Objects.requireNonNull(queue, "queue must not be null");
        this.alertBus = Objects.requireNonNull(alertBus, "alertBus must not be null");
        this.cooldownSeconds = cooldownSeconds;
        this.detectors = new CopyOnWriteArrayList<>();
        this.running = new AtomicBoolean(false);
        this.lastAlertAt = new ConcurrentHashMap<>();
        this.eventObservers = new CopyOnWriteArrayList<>();
        ConfigManager config = ConfigManager.getInstance();
        this.queuePollMillis = config.getInt("engine.queue.pollMillis", 50);
        this.workerJoinMillis = config.getInt("engine.worker.joinMillis", 1000);
    }

    public DetectionEngine(BlockingQueue<NetworkEvent> queue, AlertBus alertBus) {
        this(queue, alertBus, ConfigManager.getInstance().getInt("detection.cooldownSeconds", 5));
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
                worker.join(workerJoinMillis);
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
        droppedEvents.set(0);
    }

    public void addDetector(Detector d) {
        if (d != null) {
            detectors.add(d);
        }
    }

    /**
     * Registers a tap on the raw event stream, for telemetry that needs the
     * events themselves rather than the alerts they produce (flow accounting,
     * packet capture, replay). Observers run before the detectors and cannot
     * break detection: a failing observer is logged once and then skipped for
     * that event.
     */
    public void addEventObserver(Consumer<NetworkEvent> observer) {
        if (observer != null) {
            eventObservers.add(observer);
        }
    }

    public List<Consumer<NetworkEvent>> getEventObservers() {
        return Collections.unmodifiableList(eventObservers);
    }

    /** Installs the final filter between detection and publication. */
    public void setAlertGate(AlertGate gate) {
        this.alertGate = gate == null ? AlertGate.ALLOW_ALL : gate;
    }

    /**
     * Installs a check that runs before an event is observed or detected. It is
     * the seam containment uses to drop traffic from a blocked source, and it
     * defaults to admitting everything so the pipeline is unchanged until
     * something is installed.
     */
    public void setAdmission(Predicate<NetworkEvent> admission) {
        this.admission = admission == null ? event -> true : admission;
    }

    public Predicate<NetworkEvent> getAdmission() {
        return admission;
    }

    /** Events refused by the admission check since the last reset. */
    public long getDroppedEvents() {
        return droppedEvents.get();
    }

    public AlertGate getAlertGate() {
        return alertGate;
    }

    private void runLoop() {
        while (running.get()) {
            try {
                NetworkEvent event = queue.poll(queuePollMillis, TimeUnit.MILLISECONDS);
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
        if (!admission.test(e)) {
            droppedEvents.incrementAndGet();
            return;
        }
        notifyObservers(e);
        for (Detector detector : detectors) {
            Optional<Alert> optAlert = detector.analyze(e);
            if (optAlert.isPresent()) {
                Alert alert = optAlert.get();
                String source = alert.getSourceIp();
                Instant now = alert.getTimestamp();

                Instant lastTime = lastAlertAt.get(source);
                if (lastTime != null && cooldownSeconds > 0) {
                    Instant cooldownExpires = lastTime.plusSeconds(cooldownSeconds);
                    if (now.isBefore(cooldownExpires) || now.equals(lastTime)) {
                        continue;
                    }
                }

                // The gate looks at the alert; a suppressed alert does not
                // consume the source cooldown, so the next genuine alert for the
                // same source is not silenced by a duplicate.
                if (!alertGate.allow(alert)) {
                    continue;
                }

                lastAlertAt.put(source, now);
                alertBus.publish(alert.markSimulated(e.simulated()));
            }
        }
    }

    private void notifyObservers(NetworkEvent event) {
        for (Consumer<NetworkEvent> observer : eventObservers) {
            try {
                observer.accept(event);
            } catch (RuntimeException ex) {
                if (observerFaultLogged.compareAndSet(false, true)) {
                    EventLog.getInstance().log(LogLevel.WARN, "detection-engine",
                            "An event observer threw " + ex + "; detection continues without it.");
                }
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

