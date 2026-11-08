package pk.ooad.ntd.zeek;

import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.util.ConfigManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ZeekConnLogParser {

    private static final List<String> FALLBACK_FIELDS = List.of(
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
            "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
            "missed_bytes", "history", "orig_pkts", "resp_pkts");

    private static final int MAX_PROBLEMS = 20;
    private static final int MAX_FLOWS_PER_IMPORT = 200_000;
    private static final String FALLBACK_LABEL = "IMPORTED";

    private final int maxFlows;

    public ZeekConnLogParser() {
        this(Math.max(1, ConfigManager.getInstance().getInt("zeek.import.maxFlows", 50_000)));
    }

    public ZeekConnLogParser(int maxFlows) {
        this.maxFlows = Math.max(1, Math.min(maxFlows, MAX_FLOWS_PER_IMPORT));
    }

    public ZeekImportResult parse(Path file) throws IOException {
        String source = file == null ? "<null>" : file.getFileName().toString();
        if (file == null || !Files.isRegularFile(file)) {
            throw new IOException("Zeek log not found: " + file);
        }
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            return parse(reader, source);
        }
    }

    public ZeekImportResult parse(String content, String source) {
        if (content == null || content.isBlank()) {
            return new ZeekImportResult(source == null ? "<empty>" : source, 0, 0, 0, null, null,
                    Set.of(), List.of(), List.of());
        }
        return parse(new BufferedReader(new StringReader(content)), source == null ? "<text>" : source);
    }

    private ZeekImportResult parse(BufferedReader reader, String source) {
        List<String> fields = FALLBACK_FIELDS;
        List<FlowRecord> records = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        Set<String> hosts = new LinkedHashSet<>();
        long lines = 0;
        long skipped = 0;
        Instant first = null;
        Instant last = null;
        String separator = "\t";

        try {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("#")) {
                    if (line.startsWith("#separator")) {
                        separator = decodeSeparator(line.substring("#separator".length()).trim());
                    } else if (line.startsWith("#fields")) {
                        fields = List.of(line.substring("#fields".length()).trim().split("\\s+"));
                    }
                    continue;
                }
                if (line.isBlank()) {
                    continue;
                }
                lines++;
                if (records.size() >= maxFlows) {
                    skipped++;
                    addProblem(problems, "Import stopped at the configured maximum of " + maxFlows + " flows");
                    break;
                }
                try {
                    Map<String, String> row = row(fields, line, separator);
                    FlowRecord record = toFlow(row, records.size());
                    if (record == null) {
                        skipped++;
                        continue;
                    }
                    records.add(record);
                    hosts.add(record.srcIp());
                    hosts.add(record.dstIp());
                    if (record.startTime() != null) {
                        if (first == null || record.startTime().isBefore(first)) {
                            first = record.startTime();
                        }
                        if (last == null || record.startTime().isAfter(last)) {
                            last = record.startTime();
                        }
                    }
                } catch (RuntimeException ex) {
                    skipped++;
                    addProblem(problems, "Line " + lines + ": " + ex.getMessage());
                }
            }
        } catch (IOException ex) {
            addProblem(problems, "Read stopped early: " + ex.getMessage());
        }

        return new ZeekImportResult(source, lines, records.size(), skipped, first, last, hosts, problems, records);
    }

    private FlowRecord toFlow(Map<String, String> row, int index) {
        String src = value(row, "id.orig_h");
        String dst = value(row, "id.resp_h");
        if (src == null || dst == null) {
            return null;
        }
        Integer srcPort = port(value(row, "id.orig_p"));
        Integer dstPort = port(value(row, "id.resp_p"));
        if (srcPort == null || dstPort == null) {
            return null;
        }
        Double ts = number(value(row, "ts"));
        if (ts == null) {
            return null;
        }
        Double duration = number(value(row, "duration"));
        Instant start = Instant.ofEpochMilli(Math.round(ts * 1000.0));
        Instant end = duration == null ? start : start.plusMillis(Math.max(0L, Math.round(duration * 1000.0)));
        long bytesOut = longValue(value(row, "orig_bytes"));
        long bytesIn = longValue(value(row, "resp_bytes"));
        long packets = longValue(value(row, "orig_pkts")) + longValue(value(row, "resp_pkts"));
        String protocol = value(row, "proto");
        String uid = value(row, "uid");

        List<String> flags = new ArrayList<>(2);
        String state = value(row, "conn_state");
        if (state != null) {
            flags.add(state);
        }
        if (flags.isEmpty()) {
            flags.add("IMPORTED");
        }
        String label = value(row, "service");
        return new FlowRecord(
                uid == null ? "zeek-" + (index + 1) : uid,
                src,
                dst,
                srcPort,
                dstPort,
                protocol == null ? "unknown" : protocol.toUpperCase(),
                bytesOut,
                bytesIn,
                packets,
                start,
                end,
                flags,
                label == null ? FALLBACK_LABEL : label.toUpperCase(),
                false,
                true);
    }

    private static Map<String, String> row(List<String> fields, String line, String separator) {
        String[] cells = line.split(java.util.regex.Pattern.quote(separator), -1);
        Map<String, String> row = new HashMap<>();
        int limit = Math.min(fields.size(), cells.length);
        for (int i = 0; i < limit; i++) {
            row.put(fields.get(i), cells[i]);
        }
        return row;
    }

    private static String decodeSeparator(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "\t";
        }
        if (raw.startsWith("\\x") && raw.length() >= 4) {
            try {
                return String.valueOf((char) Integer.parseInt(raw.substring(2, 4), 16));
            } catch (NumberFormatException ex) {
                return "\t";
            }
        }
        return raw;
    }

    private static String value(Map<String, String> row, String key) {
        String raw = row.get(key);
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        return trimmed.isEmpty() || "-".equals(trimmed) || "(empty)".equals(trimmed) ? null : trimmed;
    }

    private static Double number(String raw) {
        if (raw == null) {
            return null;
        }
        try {
            return Double.valueOf(raw);
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private static Integer port(String raw) {
        if (raw == null) {
            return null;
        }
        try {
            int port = (int) Math.round(Double.parseDouble(raw));
            return port < 0 || port > 65_535 ? null : port;
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private static long longValue(String raw) {
        if (raw == null) {
            return 0L;
        }
        try {
            return (long) Math.round(Double.parseDouble(raw));
        } catch (NumberFormatException ex) {
            return 0L;
        }
    }

    private static void addProblem(List<String> problems, String message) {
        if (problems.size() < MAX_PROBLEMS) {
            problems.add(message);
        }
    }
}
