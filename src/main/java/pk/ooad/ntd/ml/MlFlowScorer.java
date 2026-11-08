package pk.ooad.ntd.ml;

import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.detection.AlertGate;
import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public final class MlFlowScorer implements AutoCloseable {

    public static final String DETECTOR_NAME = "MlFlowScorer";

    public record Status(
            boolean enabled,
            String modelState,
            int samples,
            int clusters,
            double threshold,
            String lastTrainedAt,
            long scored,
            long anomalies,
            long alerts,
            long excluded,
            String lastError) {
    }

    private final AlertBus alertBus;
    private final AlertGate gate;
    private final AlertFactory alertFactory = new AlertFactory();
    private final boolean enabled;
    private final int k;
    private final int minSamples;
    private final int retrainSeconds;
    private final double threshold;
    private final int maxTrainFlows;
    private final long seed;
    private final Severity alertSeverity;
    private final long cooldownMillis;
    private final int maxTrackedSources;
    private final boolean excludeAlerted;
    private final long exclusionMillis;
    private final int maxAlertedPairs;

    private final Deque<FlowFeatures> training = new ArrayDeque<>();
    private final AtomicBoolean trainingRunning = new AtomicBoolean(false);
    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private final AtomicLong scored = new AtomicLong();
    private final AtomicLong anomalies = new AtomicLong();
    private final AtomicLong alerts = new AtomicLong();
    private final AtomicLong excludedSamples = new AtomicLong();
    private final AtomicLong generation = new AtomicLong();
    private volatile AnomalyModel model;
    private volatile long trainingGeneration = -1;
    private volatile Instant lastTrainedAt;
    private volatile String lastError;
    private final Map<String, Instant> lastAlertAt = new HashMap<>();
    private final Map<String, Instant> alertedPairs = new HashMap<>();
    private final AlertListener alertListener = this::rememberAlertedPair;
    private Consumer<Status> listener = status -> { };
    private ScheduledExecutorService retrainer;

    public MlFlowScorer(AlertBus alertBus, AlertGate gate) {
        this(alertBus, gate, ConfigManager.getInstance());
    }

    public MlFlowScorer(AlertBus alertBus, AlertGate gate, ConfigManager config) {
        this(alertBus, gate,
                Boolean.parseBoolean(config.getString("ml.enabled", "false")),
                config.getInt("ml.k", 4),
                config.getInt("ml.minSamples", 60),
                config.getInt("ml.retrainSeconds", 300),
                config.getDouble("ml.anomalyThreshold", 0.9),
                config.getInt("ml.maxTrainFlows", 2000),
                (long) config.getInt("ml.seed", 42),
                severity(config.getString("ml.alertSeverity", "LOW")),
                config.getInt("ml.cooldownSeconds", 300),
                config.getInt("ml.maxTrackedSources", 2000),
                Boolean.parseBoolean(config.getString("ml.train.excludeAlerted", "true")),
                config.getInt("ml.train.exclusionSeconds", 300),
                config.getInt("ml.train.maxPairs", 5000));
    }

    MlFlowScorer(AlertBus alertBus, AlertGate gate, boolean enabled, int k, int minSamples,
                 int retrainSeconds, double threshold, int maxTrainFlows, long seed,
                 Severity alertSeverity, int cooldownSeconds, int maxTrackedSources) {
        this(alertBus, gate, enabled, k, minSamples, retrainSeconds, threshold, maxTrainFlows, seed,
                alertSeverity, cooldownSeconds, maxTrackedSources, true, 300, 5000);
    }

    MlFlowScorer(AlertBus alertBus, AlertGate gate, boolean enabled, int k, int minSamples,
                 int retrainSeconds, double threshold, int maxTrainFlows, long seed,
                 Severity alertSeverity, int cooldownSeconds, int maxTrackedSources,
                 boolean excludeAlerted, int exclusionSeconds, int maxAlertedPairs) {
        this.alertBus = Objects.requireNonNull(alertBus, "alertBus must not be null");
        this.gate = gate == null ? AlertGate.ALLOW_ALL : gate;
        this.enabled = enabled;
        this.k = Math.max(1, k);
        this.minSamples = Math.max(2, minSamples);
        this.retrainSeconds = Math.max(1, retrainSeconds);
        this.threshold = Math.min(1.0, Math.max(0.0, threshold));
        this.maxTrainFlows = Math.max(this.minSamples, maxTrainFlows);
        this.seed = seed;
        this.alertSeverity = alertSeverity == null ? Severity.LOW : alertSeverity;
        this.cooldownMillis = Math.max(0, cooldownSeconds) * 1000L;
        this.maxTrackedSources = Math.max(16, maxTrackedSources);
        this.excludeAlerted = excludeAlerted;
        this.exclusionMillis = Math.max(0, exclusionSeconds) * 1000L;
        this.maxAlertedPairs = Math.max(16, maxAlertedPairs);
        if (enabled) {
            startRetrainer();
            alertBus.subscribe(alertListener);
        }
    }

    public void onFlow(FlowRecord flow) {
        if (!enabled || flow == null || !flow.ended()) {
            return;
        }
        FlowFeatures features = FeatureVector.of(flow);
        if (!excludedFromTraining(flow)) {
            addTrainingSample(features);
        }
        AnomalyModel current = model;
        if (current == null) {
            if (sampleCount() >= minSamples) {
                requestTraining();
            }
            return;
        }
        double score = current.score(features);
        scored.incrementAndGet();
        if (score < threshold) {
            return;
        }
        anomalies.incrementAndGet();
        Instant when = flow.endTime() != null ? flow.endTime() : Instant.now();
        if (coolingDown(flow.srcIp(), when)) {
            return;
        }
        Alert alert = alertFactory.create(alertSeverity, AttackType.DATA_TRANSFER,
                flow.srcIp(), flow.dstIp(), DETECTOR_NAME,
                describe(flow, score), when).markSimulated(flow.simulated());
        if (!gate.allow(alert)) {
            return;
        }
        rememberAlert(flow.srcIp(), when);
        alerts.incrementAndGet();
        alertBus.publish(alert);
    }

    public boolean train() {
        if (!enabled || !trainingRunning.compareAndSet(false, true)) {
            return false;
        }
        long started = generation.get();
        trainingGeneration = started;
        try {
            List<FlowFeatures> snapshot = snapshot();
            if (snapshot.size() < minSamples) {
                return false;
            }
            AnomalyModel trained = AnomalyModel.train(snapshot, k, 30, seed);
            if (generation.get() != started) {
                return false;
            }
            model = trained;
            dirty.set(false);
            lastTrainedAt = Instant.now();
            lastError = null;
            listener.accept(status());
            return true;
        } catch (RuntimeException ex) {
            lastError = ex.getClass().getSimpleName() + ": " + ex.getMessage();
            EventLog.getInstance().log(LogLevel.WARN, "ml",
                    "Flow model training failed and the previous model stays in place: " + lastError);
            return false;
        } finally {
            trainingGeneration = -1;
            trainingRunning.set(false);
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setTrainingListener(Consumer<Status> sink) {
        this.listener = sink == null ? status -> { } : sink;
    }

    public int sampleCount() {
        synchronized (training) {
            return training.size();
        }
    }

    public double score(FlowRecord flow) {
        AnomalyModel current = model;
        if (!enabled || current == null || flow == null) {
            return 0.0;
        }
        return current.score(FeatureVector.of(flow));
    }

    public double scoreFeatures(FlowFeatures features) {
        AnomalyModel current = model;
        if (!enabled || current == null || features == null) {
            return 0.0;
        }
        return current.score(features);
    }

    public Status status() {
        AnomalyModel current = model;
        String state;
        if (!enabled) {
            state = "disabled";
        } else if (current == null) {
            state = trainingRunning.get() && trainingGeneration == generation.get() ? "training" : "cold";
        } else {
            state = "ready";
        }
        return new Status(enabled, state, sampleCount(),
                current == null ? 0 : current.clusters(),
                threshold,
                lastTrainedAt == null ? "" : lastTrainedAt.toString(),
                scored.get(), anomalies.get(), alerts.get(), excludedSamples.get(),
                lastError == null ? "" : lastError);
    }

    public void reset() {
        generation.incrementAndGet();
        synchronized (training) {
            training.clear();
        }
        synchronized (lastAlertAt) {
            lastAlertAt.clear();
        }
        synchronized (alertedPairs) {
            alertedPairs.clear();
        }
        model = null;
        lastTrainedAt = null;
        lastError = null;
        dirty.set(false);
        scored.set(0);
        anomalies.set(0);
        alerts.set(0);
        excludedSamples.set(0);
    }

    @Override
    public void close() {
        alertBus.unsubscribe(alertListener);
        if (retrainer != null) {
            retrainer.shutdownNow();
            retrainer = null;
        }
    }

    private void addTrainingSample(FlowFeatures features) {
        synchronized (training) {
            if (training.size() >= maxTrainFlows) {
                training.removeFirst();
            }
            training.addLast(features);
        }
        dirty.set(true);
    }

    private List<FlowFeatures> snapshot() {
        synchronized (training) {
            return new ArrayList<>(training);
        }
    }

    private void requestTraining() {
        if (retrainer == null || !dirty.get()) {
            return;
        }
        retrainer.execute(this::train);
    }

    private void startRetrainer() {
        retrainer = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "MlFlowScorer-Retrainer");
            thread.setDaemon(true);
            return thread;
        });
        retrainer.scheduleWithFixedDelay(() -> {
            try {
                if (dirty.get() && sampleCount() >= minSamples) {
                    train();
                }
            } catch (RuntimeException ex) {
                lastError = ex.getClass().getSimpleName() + ": " + ex.getMessage();
            }
        }, retrainSeconds, retrainSeconds, TimeUnit.SECONDS);
    }

    private boolean excludedFromTraining(FlowRecord flow) {
        if (!excludeAlerted || exclusionMillis <= 0) {
            return false;
        }
        Instant at = flow.endTime() != null ? flow.endTime() : flow.startTime();
        if (at == null) {
            return false;
        }
        Instant alertAt;
        synchronized (alertedPairs) {
            alertAt = alertedPairs.get(pairKey(flow.srcIp(), flow.dstIp()));
        }
        if (alertAt == null
                || Math.abs(Duration.between(alertAt, at).toMillis()) > exclusionMillis) {
            return false;
        }
        excludedSamples.incrementAndGet();
        return true;
    }

    private void rememberAlertedPair(Alert alert) {
        if (!excludeAlerted || alert == null) {
            return;
        }
        String key = pairKey(alert.getSourceIp(), alert.getTargetIp());
        synchronized (alertedPairs) {
            if (alertedPairs.size() >= maxAlertedPairs && !alertedPairs.containsKey(key)) {
                alertedPairs.clear();
            }
            alertedPairs.put(key, alert.getTimestamp());
        }
    }

    private static String pairKey(String source, String target) {
        return (source == null ? "" : source) + "|" + (target == null ? "" : target);
    }

    private boolean coolingDown(String source, Instant when) {
        if (source == null || cooldownMillis <= 0) {
            return false;
        }
        synchronized (lastAlertAt) {
            Instant last = lastAlertAt.get(source);
            return last != null && when.isBefore(last.plusMillis(cooldownMillis));
        }
    }

    private void rememberAlert(String source, Instant when) {
        if (source == null) {
            return;
        }
        synchronized (lastAlertAt) {
            if (lastAlertAt.size() >= maxTrackedSources && !lastAlertAt.containsKey(source)) {
                lastAlertAt.clear();
            }
            lastAlertAt.put(source, when);
        }
    }

    private String describe(FlowRecord flow, double score) {
        return "Flow anomaly score " + String.format(Locale.ROOT, "%.3f", score)
                + " for " + flow.srcIp() + ":" + flow.srcPort()
                + " -> " + flow.dstIp() + ":" + flow.dstPort()
                + " (" + flow.protocol() + ", " + flow.bytesOut() + " bytes out, "
                + flow.packets() + " packets, " + flow.durationMs() + "ms), threshold "
                + String.format(Locale.ROOT, "%.3f", threshold);
    }

    private static Severity severity(String raw) {
        if (raw == null) {
            return Severity.LOW;
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return Severity.LOW;
        }
    }
}
