package pk.ooad.ntd.flows;

import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class FlowRecorder implements Consumer<NetworkEvent> {

    public record LabelRule(String label, Pattern pattern) {
    }

    private static final String FALLBACK_LABEL = "UNCLASSIFIED";

    private final boolean enabled;
    private final long idleTimeoutMillis;
    private final int maxRecords;
    private final int maxActiveFlows;
    private final long retentionMillis;
    private final Set<Integer> udpPorts;
    private final List<LabelRule> labelRules;

    private final Map<String, Mutable> active = new LinkedHashMap<>(256, 0.75f, true);
    private final Deque<FlowRecord> closed = new ArrayDeque<>();
    private final List<Consumer<FlowRecord>> closeListeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean closeFaultLogged = new AtomicBoolean();
    private long sequence;
    private Instant watermark;
    private volatile boolean recording = true;

    public FlowRecorder() {
        this(ConfigManager.getInstance());
    }

    public FlowRecorder(ConfigManager config) {
        this(
                Boolean.parseBoolean(config.getString("flow.enabled", "true")),
                Math.max(1, config.getInt("flow.idleTimeoutSeconds", 30)),
                Math.max(1, config.getInt("flow.maxRecords", 2000)),
                Math.max(1, config.getInt("flow.maxActiveFlows", 5000)),
                Math.max(0, config.getInt("flow.retentionMinutes", 30)),
                parsePorts(config.getList("flow.udpPorts")),
                parseRules(config.getList("flow.labels"))
        );
    }

    FlowRecorder(boolean enabled, int idleTimeoutSeconds, int maxRecords, int maxActiveFlows,
                 int retentionMinutes, Set<Integer> udpPorts, List<LabelRule> labelRules) {
        this.enabled = enabled;
        this.idleTimeoutMillis = Math.max(1, idleTimeoutSeconds) * 1000L;
        this.maxRecords = Math.max(1, maxRecords);
        this.maxActiveFlows = Math.max(1, maxActiveFlows);
        this.retentionMillis = Math.max(0, retentionMinutes) * 60_000L;
        this.udpPorts = udpPorts == null ? Set.of() : Set.copyOf(udpPorts);
        this.labelRules = labelRules == null ? List.of() : List.copyOf(labelRules);
    }

    @Override
    public synchronized void accept(NetworkEvent event) {
        if (!enabled || !recording || event == null || event.timestamp() == null) {
            return;
        }
        Instant at = event.timestamp();
        String protocol = udpPorts.contains(event.port()) ? "UDP" : "TCP";
        int srcPort = ephemeralPort(event.sourceIp(), event.destIp(), event.port());
        String key = event.sourceIp() + '|' + event.destIp() + '|' + event.port() + '|' + protocol + '|' + srcPort;

        Mutable flow = active.get(key);
        if (flow != null && flow.idleFor(at) > idleTimeoutMillis) {
            close(key);
            flow = null;
        }
        if (flow == null) {
            if (active.size() >= maxActiveFlows) {
                evictLeastRecent();
            }
            flow = new Mutable("f" + (++sequence), event, srcPort, protocol, at);
            active.put(key, flow);
        }
        String label = labelFor(event);
        flow.absorb(event, at, label, labelRankFor(label));
        if (watermark == null || at.isAfter(watermark)) {
            watermark = at;
        }
        purgeExpired();
    }

    public synchronized List<FlowRecord> query(FlowQuery filter) {
        FlowQuery query = filter == null ? FlowQuery.all(maxRecords) : filter;
        expireIdle();
        int limit = query.limit() <= 0 ? maxRecords : query.limit();
        limit = Math.min(limit, maxRecords + maxActiveFlows);

        List<FlowRecord> rows = new ArrayList<>(closed.size() + active.size());
        for (FlowRecord record : closed) {
            if (query.matches(record)) {
                rows.add(record);
            }
        }
        if (query.includeActive()) {
            for (Mutable flow : active.values()) {
                FlowRecord record = flow.toRecord(false);
                if (query.matches(record)) {
                    rows.add(record);
                }
            }
        }
        rows.sort(Comparator.comparing(FlowRecord::startTime).reversed());
        return rows.size() > limit ? new ArrayList<>(rows.subList(0, limit)) : rows;
    }

    public synchronized void reset() {
        active.clear();
        closed.clear();
        sequence = 0L;
        watermark = null;
    }

    public void addCloseListener(Consumer<FlowRecord> listener) {
        if (listener != null) {
            closeListeners.add(listener);
        }
    }

    public synchronized int closeAllOpen() {
        List<String> keys = new ArrayList<>(active.keySet());
        for (String key : keys) {
            close(key);
        }
        return keys.size();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean setRecording(boolean on) {
        boolean previous = recording;
        recording = on;
        return previous;
    }

    public boolean isRecording() {
        return recording;
    }

    public synchronized int activeCount() {
        return active.size();
    }

    public synchronized int closedCount() {
        return closed.size();
    }

    public int getMaxRecords() {
        return maxRecords;
    }

    private void close(String key) {
        Mutable flow = active.remove(key);
        if (flow == null) {
            return;
        }
        FlowRecord record = flow.toRecord(true);
        closed.addLast(record);
        purgeExpired();
        while (closed.size() > maxRecords) {
            closed.removeFirst();
        }
        notifyClosed(record);
    }

    private void notifyClosed(FlowRecord record) {
        for (Consumer<FlowRecord> listener : closeListeners) {
            try {
                listener.accept(record);
            } catch (RuntimeException ex) {
                if (closeFaultLogged.compareAndSet(false, true)) {
                    EventLog.getInstance().log(LogLevel.WARN, "flow-recorder",
                            "A flow close listener threw " + ex + "; recording continues without it.");
                }
            }
        }
    }

    private void expireIdle() {
        if (watermark == null) {
            return;
        }
        List<String> stale = new ArrayList<>();
        for (Map.Entry<String, Mutable> entry : active.entrySet()) {
            if (entry.getValue().idleFor(watermark) > idleTimeoutMillis) {
                stale.add(entry.getKey());
            }
        }
        for (String key : stale) {
            close(key);
        }
    }

    private void evictLeastRecent() {
        Iterator<String> keys = active.keySet().iterator();
        if (keys.hasNext()) {
            close(keys.next());
        }
    }

    private void purgeExpired() {
        if (watermark == null) {
            return;
        }
        Instant cutoff = watermark.minusMillis(retentionMillis);
        while (!closed.isEmpty()) {
            FlowRecord oldest = closed.peekFirst();
            if (oldest == null || oldest.endTime() == null || !oldest.endTime().isBefore(cutoff)) {
                return;
            }
            closed.removeFirst();
        }
    }

    private String labelFor(NetworkEvent event) {
        String payload = event.payload();
        if (payload != null) {
            for (LabelRule rule : labelRules) {
                if (rule.pattern().matcher(payload).matches()) {
                    return rule.label();
                }
            }
        }
        return event.type() == null ? FALLBACK_LABEL : event.type().name();
    }

    private int labelRankFor(String label) {
        for (int index = 0; index < labelRules.size(); index++) {
            if (labelRules.get(index).label().equals(label)) {
                return index;
            }
        }
        return Integer.MAX_VALUE;
    }

    static int ephemeralPort(String srcIp, String dstIp, int dstPort) {
        int hash = 17;
        hash = 31 * hash + (srcIp == null ? 0 : srcIp.hashCode());
        hash = 31 * hash + (dstIp == null ? 0 : dstIp.hashCode());
        hash = 31 * hash + dstPort;
        return 1024 + Math.floorMod(hash, 64_000 - 1024);
    }

    private static Set<Integer> parsePorts(List<String> raw) {
        Set<Integer> ports = new HashSet<>();
        for (String item : raw) {
            try {
                int port = Integer.parseInt(item.trim());
                if (port > 0 && port <= 65_535) {
                    ports.add(port);
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return ports;
    }

    private static List<LabelRule> parseRules(List<String> raw) {
        List<LabelRule> rules = new ArrayList<>();
        for (String item : raw) {
            int split = item.indexOf('=');
            if (split <= 0 || split == item.length() - 1) {
                continue;
            }
            String label = item.substring(0, split).trim();
            String regex = item.substring(split + 1).trim();
            if (label.isEmpty() || regex.isEmpty()) {
                continue;
            }
            try {
                rules.add(new LabelRule(label, Pattern.compile(regex)));
            } catch (PatternSyntaxException ignored) {
            }
        }
        return rules;
    }

    private static final class Mutable {
        private final String id;
        private final String srcIp;
        private final String dstIp;
        private final int srcPort;
        private final int dstPort;
        private final String protocol;
        private Instant start;
        private Instant lastSeen;
        private long bytesOut;
        private long packets;
        private long failures;
        private long successes;
        private String label;
        private int labelRank = Integer.MAX_VALUE;
        private boolean simulated;

        private Mutable(String id, NetworkEvent event, int srcPort, String protocol, Instant at) {
            this.id = id;
            this.srcIp = event.sourceIp();
            this.dstIp = event.destIp();
            this.srcPort = srcPort;
            this.dstPort = event.port();
            this.protocol = protocol;
            this.start = at;
            this.lastSeen = at;
        }

        private void absorb(NetworkEvent event, Instant at, String candidateLabel, int candidateRank) {
            if (at.isBefore(start)) {
                start = at;
            }
            if (at.isAfter(lastSeen)) {
                lastSeen = at;
            }
            bytesOut += Math.max(0L, event.bytes());
            packets++;
            if (event.success()) {
                successes++;
            } else {
                failures++;
            }
            simulated = simulated || event.simulated();
            if (label == null || candidateRank < labelRank) {
                label = candidateLabel;
                labelRank = candidateRank;
            }
        }

        private long idleFor(Instant at) {
            return Math.max(0L, Duration.between(lastSeen, at).toMillis());
        }

        private FlowRecord toRecord(boolean ended) {
            List<String> flags = new ArrayList<>(2);
            if (successes > 0) {
                flags.add("OK");
            }
            if (failures > 0) {
                flags.add("FAILED");
            }
            return new FlowRecord(id, srcIp, dstIp, srcPort, dstPort, protocol, bytesOut, 0L, packets,
                    start, lastSeen, flags, label == null ? FALLBACK_LABEL : label, simulated, ended);
        }
    }
}
