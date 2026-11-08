package pk.ooad.ntd.forensics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.persistence.AlertRecord;
import pk.ooad.ntd.security.AuditLog;
import pk.ooad.ntd.service.Incident;
import pk.ooad.ntd.util.ConfigManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class EvidenceExporter {

    public record Bundle(String directory, String createdAt, int files, long bytes,
                         String manifestSha256, String actor) {
    }

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'", Locale.ROOT).withZone(ZoneOffset.UTC);

    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private final boolean enabled;
    private final Path directory;
    private final int maxFlows;
    private final int maxAlerts;

    public EvidenceExporter(ConfigManager config) {
        this(Boolean.parseBoolean(config.getString("forensics.enabled", "false")),
                Path.of(config.getString("forensics.dir", "evidence")),
                config.getInt("forensics.maxFlows", 5000),
                config.getInt("forensics.maxAlerts", 5000));
    }

    public EvidenceExporter(boolean enabled, Path directory, int maxFlows, int maxAlerts) {
        this.enabled = enabled;
        this.directory = directory == null ? Path.of("evidence") : directory;
        this.maxFlows = Math.max(1, maxFlows);
        this.maxAlerts = Math.max(1, maxAlerts);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Path directory() {
        return directory;
    }

    public Bundle export(String actor, List<FlowRecord> flows, List<AlertRecord> alerts,
                         List<AuditLog.Entry> audit, List<Incident> incidents) {
        if (!enabled) {
            throw new IllegalStateException("evidence export is disabled");
        }
        Instant now = Instant.now();
        Path target = uniqueDirectory(now, actor);
        List<FlowRecord> flowRows = cap(flows, maxFlows);
        List<AlertRecord> alertRows = cap(alerts, maxAlerts);
        List<AuditLog.Entry> auditRows = audit == null ? List.of() : new ArrayList<>(audit);
        List<Incident> incidentRows = incidents == null ? List.of() : new ArrayList<>(incidents);

        Map<String, Map<String, Object>> files = new LinkedHashMap<>();
        long bytes = 0;
        try {
            Files.createDirectories(target);
            bytes += write(target, "flows.json", flowPayload(flowRows), files);
            bytes += write(target, "alerts.json", alertPayload(alertRows), files);
            bytes += write(target, "audit.json", auditPayload(auditRows), files);
            bytes += write(target, "incidents.json", incidentPayload(incidentRows), files);

            Map<String, Object> manifest = new LinkedHashMap<>();
            manifest.put("formatVersion", 1);
            manifest.put("createdAt", now.toString());
            manifest.put("actor", actor == null ? "" : actor);
            manifest.put("flowCount", flowRows.size());
            manifest.put("alertCount", alertRows.size());
            manifest.put("auditCount", auditRows.size());
            manifest.put("incidentCount", incidentRows.size());
            manifest.put("flowsTruncated", flows != null && flows.size() > flowRows.size());
            manifest.put("alertsTruncated", alerts != null && alerts.size() > alertRows.size());
            manifest.put("files", files);
            byte[] manifestBytes = mapper.writeValueAsString(manifest).getBytes(StandardCharsets.UTF_8);
            Files.write(target.resolve("manifest.json"), manifestBytes);
            bytes += manifestBytes.length;
            return new Bundle(target.toString(), now.toString(), 5, bytes,
                    sha256(manifestBytes), actor == null ? "" : actor);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to export evidence to " + target, ex);
        }
    }

    private long write(Path target, String name, Object payload,
                       Map<String, Map<String, Object>> files) throws IOException {
        byte[] content = mapper.writeValueAsString(payload).getBytes(StandardCharsets.UTF_8);
        Files.write(target.resolve(name), content);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("bytes", content.length);
        entry.put("sha256", sha256(content));
        files.put(name, entry);
        return content.length;
    }

    private Path uniqueDirectory(Instant now, String actor) {
        String base = "bundle-" + STAMP.format(now);
        Path candidate = directory.resolve(base);
        int suffix = 1;
        while (Files.exists(candidate)) {
            candidate = directory.resolve(base + "-" + suffix);
            suffix++;
        }
        return candidate;
    }

    private List<Map<String, Object>> flowPayload(List<FlowRecord> flows) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (FlowRecord flow : flows) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", flow.id());
            row.put("srcIp", flow.srcIp());
            row.put("dstIp", flow.dstIp());
            row.put("srcPort", flow.srcPort());
            row.put("dstPort", flow.dstPort());
            row.put("protocol", flow.protocol());
            row.put("bytesOut", flow.bytesOut());
            row.put("bytesIn", flow.bytesIn());
            row.put("packets", flow.packets());
            row.put("startTime", flow.startTime() == null ? null : flow.startTime().toString());
            row.put("endTime", flow.endTime() == null ? null : flow.endTime().toString());
            row.put("durationMs", flow.durationMs());
            row.put("flags", flow.flags());
            row.put("label", flow.label());
            row.put("simulated", flow.simulated());
            row.put("ended", flow.ended());
            rows.add(row);
        }
        return rows;
    }

    private List<Map<String, Object>> alertPayload(List<AlertRecord> alerts) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (AlertRecord alert : alerts) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", alert.id());
            row.put("timestamp", alert.timestamp() == null ? null : alert.timestamp().toString());
            row.put("severity", alert.severity());
            row.put("attackType", alert.attackType());
            row.put("sourceIp", alert.sourceIp());
            row.put("targetIp", alert.targetIp());
            row.put("detector", alert.detector());
            row.put("description", alert.description());
            row.put("simulated", alert.simulated());
            rows.add(row);
        }
        return rows;
    }

    private List<Map<String, Object>> auditPayload(List<AuditLog.Entry> entries) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (AuditLog.Entry entry : entries) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sequence", entry.sequence());
            row.put("timestamp", entry.timestamp() == null ? null : entry.timestamp().toString());
            row.put("actor", entry.actor());
            row.put("action", entry.action());
            row.put("target", entry.target());
            row.put("outcome", entry.outcome());
            row.put("detail", entry.detail());
            rows.add(row);
        }
        return rows;
    }

    private List<Map<String, Object>> incidentPayload(List<Incident> incidents) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Incident incident : incidents) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", incident.getId());
            row.put("sourceIp", incident.getSourceIp());
            row.put("openedAt", incident.getOpenedAt() == null ? null : incident.getOpenedAt().toString());
            row.put("status", incident.getStatus() == null ? "" : incident.getStatus().name());
            row.put("highestSeverity", incident.getHighestSeverity() == null
                    ? "" : incident.getHighestSeverity().name());
            List<String> alertIds = new ArrayList<>();
            for (Alert alert : incident.getAlerts()) {
                alertIds.add(alert.getId());
            }
            row.put("alertIds", alertIds);
            rows.add(row);
        }
        return rows;
    }

    private static <T> List<T> cap(List<T> source, int maximum) {
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        return source.size() <= maximum ? new ArrayList<>(source) : new ArrayList<>(source.subList(0, maximum));
    }

    private static String sha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(content);
            StringBuilder out = new StringBuilder(hashed.length * 2);
            for (byte b : hashed) {
                out.append(Character.forDigit((b >> 4) & 0xF, 16));
                out.append(Character.forDigit(b & 0xF, 16));
            }
            return out.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }
}
