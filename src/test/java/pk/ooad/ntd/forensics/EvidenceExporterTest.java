package pk.ooad.ntd.forensics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.persistence.AlertRecord;
import pk.ooad.ntd.security.AuditLog;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EvidenceExporterTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final Instant base = Instant.parse("2026-11-08T04:00:00Z");

    @TempDir
    Path temp;

    private static FlowRecord flow(String id, Instant start, boolean simulated) {
        return new FlowRecord(id, "10.0.0.5", "198.51.100.9", 40_000, 443, "TCP", 2_048, 0, 5,
                start, start.plusSeconds(2), List.of("OK"), "REQUEST", simulated, true);
    }

    private List<AlertRecord> alerts() {
        Alert alert = new AlertFactory().create(Severity.CRITICAL, AttackType.DATA_TRANSFER,
                "10.0.0.5", "198.51.100.9", "DataExfilDetector", "outbound volume", base);
        return List.of(AlertRecord.from(alert));
    }

    private List<AuditLog.Entry> audit() {
        AuditLog log = new AuditLog(true, 20);
        log.record("admin", "evidence.export", "evidence", AuditLog.Outcome.ALLOWED, "manual");
        log.record("viewer", "audit.read", "audit", AuditLog.Outcome.DENIED, "role Viewer");
        return log.recent(10);
    }

    @Test
    @DisplayName("A disabled exporter refuses to write")
    void disabledExporterThrows() {
        EvidenceExporter exporter = new EvidenceExporter(false, temp.resolve("evidence"), 10, 10);
        assertFalse(exporter.isEnabled());
        assertThrows(IllegalStateException.class,
                () -> exporter.export("admin", List.of(), List.of(), List.of(), List.of()));
    }

    @Test
    @DisplayName("A bundle carries four payload files and a digest manifest")
    void bundleIsSelfDescribing() throws Exception {
        EvidenceExporter exporter = new EvidenceExporter(true, temp.resolve("evidence"), 100, 100);
        List<FlowRecord> flows = List.of(flow("f1", base, true), flow("f2", base.plusSeconds(10), false));

        EvidenceExporter.Bundle bundle = exporter.export("admin", flows, alerts(), audit(), List.of());
        assertEquals(5, bundle.files());
        assertEquals("admin", bundle.actor());
        assertTrue(bundle.bytes() > 0);

        Path dir = Path.of(bundle.directory());
        assertTrue(Files.isDirectory(dir));
        assertTrue(dir.getFileName().toString().startsWith("bundle-"));
        for (String name : List.of("flows.json", "alerts.json", "audit.json", "incidents.json", "manifest.json")) {
            assertTrue(Files.isRegularFile(dir.resolve(name)), name + " must exist");
        }

        JsonNode manifest = mapper.readTree(dir.resolve("manifest.json").toFile());
        assertEquals(1, manifest.get("formatVersion").asInt());
        assertEquals("admin", manifest.get("actor").asText());
        assertEquals(2, manifest.get("flowCount").asInt());
        assertEquals(1, manifest.get("alertCount").asInt());
        assertEquals(2, manifest.get("auditCount").asInt());
        assertEquals(0, manifest.get("incidentCount").asInt());
        assertFalse(manifest.get("flowsTruncated").asBoolean());
        assertFalse(manifest.get("alertsTruncated").asBoolean());

        for (String name : List.of("flows.json", "alerts.json", "audit.json", "incidents.json")) {
            JsonNode entry = manifest.get("files").get(name);
            byte[] content = Files.readAllBytes(dir.resolve(name));
            assertEquals(content.length, entry.get("bytes").asInt());
            assertEquals(sha256(content), entry.get("sha256").asText(), name + " digest must match");
        }
        assertEquals(sha256(Files.readAllBytes(dir.resolve("manifest.json"))), bundle.manifestSha256());

        JsonNode flowRows = mapper.readTree(dir.resolve("flows.json").toFile());
        assertEquals(2, flowRows.size());
        assertTrue(flowRows.get(0).get("simulated").asBoolean(), "the simulated flag is preserved");
        assertFalse(flowRows.get(1).get("simulated").asBoolean());
        assertEquals(2_000, flowRows.get(0).get("durationMs").asLong());

        JsonNode alertRows = mapper.readTree(dir.resolve("alerts.json").toFile());
        assertEquals("CRITICAL", alertRows.get(0).get("severity").asText());
        assertEquals("DataExfilDetector", alertRows.get(0).get("detector").asText());
    }

    @Test
    @DisplayName("The row cap is applied and declared in the manifest")
    void truncationIsDeclared() throws Exception {
        EvidenceExporter exporter = new EvidenceExporter(true, temp.resolve("evidence"), 1, 1);
        List<FlowRecord> flows = List.of(
                flow("f1", base, false),
                flow("f2", base.plusSeconds(5), false),
                flow("f3", base.plusSeconds(10), false));

        EvidenceExporter.Bundle bundle = exporter.export("admin", flows, twoAlerts(), audit(), List.of());
        JsonNode manifest = mapper.readTree(Path.of(bundle.directory()).resolve("manifest.json").toFile());
        assertEquals(1, manifest.get("flowCount").asInt());
        assertEquals(1, manifest.get("alertCount").asInt());
        assertTrue(manifest.get("flowsTruncated").asBoolean());
        assertTrue(manifest.get("alertsTruncated").asBoolean());
    }

    private List<AlertRecord> twoAlerts() {
        Alert second = new AlertFactory().create(Severity.HIGH, AttackType.PORT_SCAN,
                "10.0.0.6", "10.0.0.9", "PortScanDetector", "scan", base.plusSeconds(1));
        List<AlertRecord> rows = new java.util.ArrayList<>(alerts());
        rows.add(AlertRecord.from(second));
        return rows;
    }

    @Test
    @DisplayName("Two exports never share a directory")
    void exportsDoNotCollide() {
        EvidenceExporter exporter = new EvidenceExporter(true, temp.resolve("evidence"), 10, 10);
        EvidenceExporter.Bundle first = exporter.export("admin", List.of(), List.of(), List.of(), List.of());
        EvidenceExporter.Bundle second = exporter.export("admin", List.of(), List.of(), List.of(), List.of());
        assertNotEquals(first.directory(), second.directory());
        assertTrue(Files.isDirectory(Path.of(first.directory())));
        assertTrue(Files.isDirectory(Path.of(second.directory())));
    }

    @Test
    @DisplayName("Null inputs export empty files rather than failing")
    void nullInputsBecomeEmptyFiles() throws Exception {
        EvidenceExporter exporter = new EvidenceExporter(true, temp.resolve("evidence"), 10, 10);
        EvidenceExporter.Bundle bundle = exporter.export(null, null, null, null, null);
        JsonNode manifest = mapper.readTree(Path.of(bundle.directory()).resolve("manifest.json").toFile());
        assertEquals(0, manifest.get("flowCount").asInt());
        assertEquals("", manifest.get("actor").asText());
        Map<String, JsonNode> files = new java.util.LinkedHashMap<>();
        manifest.get("files").fields().forEachRemaining(entry -> files.put(entry.getKey(), entry.getValue()));
        assertEquals(4, files.size());
    }

    private static String sha256(byte[] content) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashed = digest.digest(content);
        StringBuilder out = new StringBuilder(hashed.length * 2);
        for (byte value : hashed) {
            out.append(Character.forDigit((value >> 4) & 0xF, 16));
            out.append(Character.forDigit(value & 0xF, 16));
        }
        return out.toString();
    }

    @Test
    @DisplayName("The manifest is valid UTF-8 JSON with a trailing newline-free body")
    void manifestIsUtf8() throws Exception {
        EvidenceExporter exporter = new EvidenceExporter(true, temp.resolve("evidence"), 10, 10);
        EvidenceExporter.Bundle bundle = exporter.export("admin", List.of(), List.of(), List.of(), List.of());
        byte[] raw = Files.readAllBytes(Path.of(bundle.directory()).resolve("manifest.json"));
        String text = new String(raw, StandardCharsets.UTF_8);
        assertTrue(text.contains("\"formatVersion\""));
        assertTrue(text.trim().endsWith("}"));
    }
}
