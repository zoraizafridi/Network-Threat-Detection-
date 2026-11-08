package pk.ooad.ntd.imports;

import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.detection.DetectionEngine;
import pk.ooad.ntd.domain.AssetFactory;
import pk.ooad.ntd.domain.AssetType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.flows.FlowRecorder;
import pk.ooad.ntd.persistence.PersistenceService;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.zeek.ZeekConnLogParser;
import pk.ooad.ntd.zeek.ZeekImportResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public final class ImportService {

    public enum State { IDLE, RUNNING, DONE, FAILED, CANCELLED }

    public record LabelStat(String label, long flows, long alerts) {
    }

    public record LabeledFlow(FlowRecord flow, String label, boolean ruleAlerted, String runId,
                              String source) {
    }

    public interface SampleSink {
        void accept(LabeledFlow sample);
    }

    public interface FlowSink {
        void record(FlowRecord flow);

        void history(FlowRecord flow);
    }

    public record Report(
            String source,
            String labelsSource,
            int flows,
            int skipped,
            int events,
            int unknownHosts,
            int stored,
            long detected,
            long alerts,
            boolean paced,
            double speed,
            long elapsedMillis,
            boolean completed,
            Instant firstTimestamp,
            Instant lastTimestamp,
            List<String> unknownHostIps,
            List<String> problems,
            List<LabelStat> labels) {

        public Report {
            unknownHostIps = unknownHostIps == null ? List.of() : List.copyOf(unknownHostIps);
            problems = problems == null ? List.of() : List.copyOf(problems);
            labels = labels == null ? List.of() : List.copyOf(labels);
        }

        public long folded() {
            return Math.max(0L, detected - alerts);
        }

        public String summary() {
            StringBuilder text = new StringBuilder();
            text.append(source).append(": ").append(flows).append(" flows, ").append(events)
                    .append(" events replayed, ").append(detected).append(" detected, ")
                    .append(alerts).append(" delivered");
            if (folded() > 0) {
                text.append(" (").append(folded()).append(" folded)");
            }
            text.append(", ").append(unknownHosts).append(" new hosts, ").append(stored).append(" rows stored");
            text.append(paced
                    ? String.format(Locale.ROOT, ", paced at %.2fx", speed)
                    : ", replayed as fast as the pipeline accepts");
            text.append(", ").append(elapsedMillis).append(" ms");
            if (!completed) {
                text.append(" (did not finish)");
            }
            return text.toString();
        }
    }

    public record Status(
            State state,
            String source,
            int flows,
            int replayed,
            long alerts,
            boolean paced,
            double speed,
            long elapsedMillis,
            String error) {

        public double progress() {
            return flows <= 0 ? 0.0 : Math.min(1.0, (double) replayed / flows);
        }
    }

    private static final String UNLABELLED = "UNLABELLED";
    private static final FlowSink NO_OP_FLOW_SINK = new FlowSink() {
        @Override
        public void record(FlowRecord flow) {
        }

        @Override
        public void history(FlowRecord flow) {
        }
    };
    private static final Pattern NON_ID = Pattern.compile("[^0-9A-Za-z]");

    private final Network network;
    private final DetectionEngine engine;
    private final AlertBus alertBus;
    private final FlowRecorder flowRecorder;
    private final PersistenceService persistence;
    private final ConfigManager config;
    private final ZeekConnLogParser parser;
    private final AssetFactory assets = new AssetFactory();
    private final Set<String> failureStates;
    private final int maxUnknownHosts;
    private final int unknownHostCriticality;
    private final long maxGapMillis;
    private final long cancelJoinMillis;

    private final Set<String> addedAssets = ConcurrentHashMap.newKeySet();
    private final AtomicLong alerts = new AtomicLong();
    private final AtomicLong replayed = new AtomicLong();
    private final Object gate = new Object();

    private volatile State state = State.IDLE;
    private volatile String error;
    private volatile String source;
    private volatile int plannedFlows;
    private volatile boolean paced;
    private volatile double speed;
    private volatile long startedAtMillis;
    private volatile long elapsedMillis;
    private volatile boolean cancelled;
    private volatile Thread worker;
    private volatile Report lastReport;
    private Consumer<Report> completionListener = report -> { };
    private volatile SampleSink sampleSink = sample -> { };
    private volatile FlowSink flowSink = NO_OP_FLOW_SINK;
    private long nextEventId = 1L;

    public ImportService(Network network, DetectionEngine engine, FlowRecorder flowRecorder,
                         PersistenceService persistence) {
        this(network, engine, flowRecorder, persistence, ConfigManager.getInstance());
    }

    ImportService(Network network, DetectionEngine engine, FlowRecorder flowRecorder,
                  PersistenceService persistence, ConfigManager config) {
        this.network = network;
        this.engine = engine;
        this.alertBus = engine.getAlertBus();
        this.flowRecorder = flowRecorder;
        this.persistence = persistence;
        this.config = config;
        this.parser = new ZeekConnLogParser(Math.max(1, config.getInt("zeek.import.maxFlows", 50_000)));
        this.failureStates = states(config.getString("import.failureStates", "S0,REJ,RSTO,RSTR"));
        this.maxUnknownHosts = Math.max(0, config.getInt("import.unknownHosts.max", 500));
        this.unknownHostCriticality = Math.max(1, config.getInt("import.unknownHosts.criticality", 1));
        this.maxGapMillis = Math.max(0L, config.getInt("import.replay.maxGapMillis", 5000));
        this.cancelJoinMillis = Math.max(1L, config.getInt("import.cancelJoinMillis", 2000));
    }

    public void setCompletionListener(Consumer<Report> listener) {
        this.completionListener = listener == null ? report -> { } : listener;
    }

    public void setSampleSink(SampleSink sink) {
        this.sampleSink = sink == null ? sample -> { } : sink;
    }

    public void setFlowSink(FlowSink sink) {
        this.flowSink = sink == null ? NO_OP_FLOW_SINK : sink;
    }

    public Report replayFile(Path connLog, Path labels, double pace) throws IOException {
        if (!Boolean.parseBoolean(config.getString("zeek.enabled", "true"))) {
            throw new IOException("The importer is switched off; set zeek.enabled=true to use it");
        }
        if (connLog == null || !Files.isRegularFile(connLog)) {
            throw new IOException("Flow log not found: " + connLog);
        }
        String connText = Files.readString(connLog, StandardCharsets.UTF_8);
        String labelsText = null;
        String labelsName = null;
        if (labels != null) {
            if (!Files.isRegularFile(labels)) {
                throw new IOException("Label file not found: " + labels);
            }
            labelsText = Files.readString(labels, StandardCharsets.UTF_8);
            labelsName = labels.getFileName().toString();
        }
        return replay(connText, connLog.getFileName().toString(), labelsText, labelsName, pace);
    }

    public Report replay(String connLog, String sourceName, String labelsText, String labelsName, double pace) {
        synchronized (gate) {
            if (state == State.RUNNING) {
                throw new IllegalStateException("An import is already running");
            }
            begin(sourceName, pace);
            try {
                return finish(run(connLog, labelsText, labelsName, pace));
            } catch (RuntimeException ex) {
                return abandon(ex);
            }
        }
    }

    public Status start(String connLog, String sourceName, String labelsText, String labelsName, double pace) {
        synchronized (gate) {
            if (state == State.RUNNING) {
                throw new IllegalStateException("An import is already running");
            }
            begin(sourceName, pace);
            Thread thread = new Thread(() -> {
                try {
                    finish(run(connLog, labelsText, labelsName, pace));
                } catch (RuntimeException ex) {
                    abandon(ex);
                }
            }, "ImportService-replay");
            thread.setDaemon(true);
            worker = thread;
            thread.start();
            return status();
        }
    }

    public Status status() {
        long elapsed = state == State.RUNNING
                ? Math.max(0L, System.currentTimeMillis() - startedAtMillis)
                : elapsedMillis;
        return new Status(state, source, plannedFlows, (int) Math.min(replayed.get(), plannedFlows),
                alerts.get(), paced, speed, elapsed, error);
    }

    public Report lastReport() {
        return lastReport;
    }

    public boolean isRunning() {
        return state == State.RUNNING;
    }

    public List<String> importedAssetIds() {
        return List.copyOf(addedAssets);
    }

    public void reset() {
        cancel();
        for (String id : new ArrayList<>(addedAssets)) {
            network.removeAsset(id);
        }
        addedAssets.clear();
        alerts.set(0);
        replayed.set(0);
        plannedFlows = 0;
        elapsedMillis = 0;
        startedAtMillis = 0L;
        state = State.IDLE;
        error = null;
        source = null;
        lastReport = null;
        cancelled = false;
        nextEventId = 1L;
    }

    public void cancel() {
        cancelled = true;
        Thread thread = worker;
        if (thread == null || thread == Thread.currentThread()) {
            worker = null;
            return;
        }
        thread.interrupt();
        try {
            thread.join(cancelJoinMillis);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        worker = null;
    }

    private void begin(String sourceName, double pace) {
        state = State.RUNNING;
        source = sourceName == null || sourceName.isBlank() ? "uploaded conn.log" : sourceName;
        plannedFlows = 0;
        alerts.set(0);
        replayed.set(0);
        paced = pace > 0;
        speed = pace;
        startedAtMillis = System.currentTimeMillis();
        elapsedMillis = 0L;
        cancelled = false;
        error = null;
    }

    private Report finish(Report report) {
        lastReport = report;
        if (state == State.RUNNING) {
            state = report.completed() ? State.DONE : State.CANCELLED;
        }
        elapsedMillis = report.elapsedMillis();
        notifyCompletion(report);
        return report;
    }

    private Report abandon(RuntimeException ex) {
        error = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
        state = State.FAILED;
        elapsedMillis = Math.max(0L, System.currentTimeMillis() - startedAtMillis);
        Report report = new Report(source, null, 0, 0, 0, 0, 0, 0L, 0L, paced, speed, elapsedMillis, false,
                null, null, List.of(), List.of(error), List.of());
        lastReport = report;
        notifyCompletion(report);
        return report;
    }

    private void notifyCompletion(Report report) {
        try {
            completionListener.accept(report);
        } catch (RuntimeException ignored) {
        }
    }

    private void notifySample(LabeledFlow sample) {
        try {
            sampleSink.accept(sample);
        } catch (RuntimeException ignored) {
        }
    }

    private void notifyFlow(FlowRecord flow, boolean storedRows) {
        try {
            flowSink.record(flow);
            if (!storedRows) {
                flowSink.history(flow);
            }
        } catch (RuntimeException ignored) {
        }
    }

    private Report run(String connLog, String labelsText, String labelsName, double pace) {
        ZeekImportResult parsed = parser.parse(connLog == null ? "" : connLog, source);
        plannedFlows = parsed.records().size();
        ImportLabels.Parsed ground = ImportLabels.parse(labelsText, labelsName);
        List<String> problems = new ArrayList<>(parsed.problems());
        problems.addAll(ground.problems());

        List<FlowRecord> records = parsed.records();
        List<String> unknown = new ArrayList<>();
        int added = addUnknownHosts(records, unknown, problems);
        int stored = store(records, problems);

        Map<String, long[]> perLabel = new LinkedHashMap<>();
        for (String label : new TreeSet<>(ground.labels().values())) {
            perLabel.put(label, new long[2]);
        }
        perLabel.putIfAbsent(UNLABELLED, new long[2]);

        boolean storedRows = stored > 0;
        boolean wasRecording = flowRecorder.setRecording(false);
        AtomicLong published = new AtomicLong();
        AlertListener counter = alert -> published.incrementAndGet();
        alertBus.subscribe(counter);
        long detectedBefore = engine.getDetectedAlerts();
        String runId = source + "#" + startedAtMillis;

        int events = 0;
        boolean completed = true;
        Instant previousStamp = null;
        try {
            for (FlowRecord flow : records) {
                if (cancelled || Thread.currentThread().isInterrupted()) {
                    completed = false;
                    break;
                }
                if (paced) {
                    pause(gapMillis(previousStamp, flow.startTime(), pace));
                }
                previousStamp = flow.startTime();
                long before = published.get();
                try {
                    engine.processNow(event(flow));
                } catch (RuntimeException ex) {
                    problems.add("Replay stopped at event " + (events + 1) + ": " + ex.getMessage());
                    completed = false;
                    break;
                }
                events++;
                long produced = published.get() - before;
                String flowLabel = labelOf(ground.labels(), flow);
                long[] row = perLabel.computeIfAbsent(flowLabel, key -> new long[2]);
                row[0]++;
                row[1] += produced;
                notifyFlow(flow, storedRows);
                notifySample(new LabeledFlow(flow, flowLabel, produced > 0, runId, source));
                replayed.set(events);
                alerts.set(published.get());
            }
        } finally {
            alertBus.unsubscribe(counter);
            flowRecorder.setRecording(wasRecording);
        }

        List<LabelStat> labels = new ArrayList<>();
        for (Map.Entry<String, long[]> entry : perLabel.entrySet()) {
            long[] row = entry.getValue();
            if (row[0] == 0L && row[1] == 0L) {
                continue;
            }
            labels.add(new LabelStat(entry.getKey(), row[0], row[1]));
        }
        labels.sort(Comparator.comparingLong(LabelStat::flows).reversed()
                .thenComparing(LabelStat::label));

        long elapsed = Math.max(0L, System.currentTimeMillis() - startedAtMillis);
        int flows = (int) Math.min(Integer.MAX_VALUE, parsed.flowsParsed());
        long detected = Math.max(0L, engine.getDetectedAlerts() - detectedBefore);
        return new Report(source, labelsName, flows, (int) Math.min(Integer.MAX_VALUE, parsed.skipped()),
                events, added, stored, detected, published.get(), paced, pace, elapsed, completed,
                parsed.firstTimestamp(), parsed.lastTimestamp(), unknown, problems, labels);
    }

    private int store(List<FlowRecord> records, List<String> problems) {
        if (records.isEmpty() || !persistence.isEnabled()) {
            return 0;
        }
        try {
            return persistence.importFlows(records);
        } catch (RuntimeException ex) {
            problems.add("Flows were parsed but not stored: " + ex.getMessage());
            return 0;
        }
    }

    private int addUnknownHosts(List<FlowRecord> records, List<String> unknown, List<String> problems) {
        int added = 0;
        Set<String> seen = new LinkedHashSet<>();
        for (FlowRecord flow : records) {
            for (String ip : new String[]{flow.srcIp(), flow.dstIp()}) {
                if (ip == null || ip.isBlank() || !seen.add(ip) || network.findByIp(ip) != null) {
                    continue;
                }
                if (added >= maxUnknownHosts) {
                    problems.add("Stopped adding hosts at the configured maximum of " + maxUnknownHosts);
                    return added;
                }
                String id = "import-" + NON_ID.matcher(ip).replaceAll("-");
                if (network.getAsset(id) != null) {
                    continue;
                }
                NetworkAsset asset = assets.create(AssetType.WORKSTATION, id, "Imported host " + ip, ip,
                        unknownHostCriticality);
                network.addAsset(asset);
                addedAssets.add(id);
                unknown.add(ip);
                added++;
            }
        }
        return added;
    }

    private NetworkEvent event(FlowRecord flow) {
        EventType type = flow.bytesOut() > 0L ? EventType.DATA_TRANSFER : EventType.CONNECT;
        Instant at = flow.startTime() == null ? Instant.now() : flow.startTime();
        return new NetworkEvent(nextEventId++, at, flow.srcIp(), flow.dstIp(), flow.dstPort(),
                Math.max(0L, flow.bytesOut()), type, !failed(flow.flags()), "", false);
    }

    private boolean failed(List<String> flags) {
        if (flags == null || flags.isEmpty() || failureStates.isEmpty()) {
            return false;
        }
        return failureStates.contains(flags.get(0).trim().toUpperCase(Locale.ROOT));
    }

    private static String labelOf(Map<String, String> labels, FlowRecord flow) {
        String label = labels.get(flow.id());
        return label == null || label.isBlank() ? UNLABELLED : label;
    }

    private long gapMillis(Instant previous, Instant next, double pace) {
        if (previous == null || next == null || pace <= 0) {
            return 0L;
        }
        long raw = Duration.between(previous, next).toMillis();
        if (raw <= 0L) {
            return 0L;
        }
        long scaled = Math.round(raw / pace);
        return Math.max(0L, Math.min(scaled, maxGapMillis));
    }

    private void pause(long millis) {
        if (millis <= 0L) {
            return;
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private static Set<String> states(String raw) {
        Set<String> values = new LinkedHashSet<>();
        if (raw == null || raw.isBlank()) {
            return Set.of();
        }
        for (String part : raw.split(",")) {
            String value = part.trim().toUpperCase(Locale.ROOT);
            if (!value.isEmpty()) {
                values.add(value);
            }
        }
        return Set.copyOf(values);
    }
}
