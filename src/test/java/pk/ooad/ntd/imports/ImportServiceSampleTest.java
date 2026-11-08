package pk.ooad.ntd.imports;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.util.ConfigManager;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImportServiceSampleTest {

    @AfterEach
    void restoreConfig() {
        ConfigManager.getInstance().reload();
    }

    private static String bundled(String name) throws IOException {
        try (InputStream input = ImportServiceSampleTest.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(input, "the bundled sample " + name + " must be on the classpath");
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    @DisplayName("The sample replay detects all attack labels and keeps traps silent")
    void sampleReplayDetectsAttacksAndKeepsTrapsQuiet() throws IOException {
        java.nio.file.Path replayConfig = java.nio.file.Path.of("config/replay.properties");
        if (!java.nio.file.Files.exists(replayConfig)) {
            replayConfig = java.nio.file.Path.of("threat-detection/config/replay.properties");
        }
        ConfigManager.getInstance().overlay(replayConfig.toString());

        List<pk.ooad.ntd.domain.Alert> delivered = new CopyOnWriteArrayList<>();
        IncidentResponseFacade facade = new IncidentResponseFacade(TopologyLoader.loadSample(), 42L);
        facade.addAlertListener(delivered::add);

        ImportService.Report report;
        try {
            report = facade.getImportService().replay(
                    bundled("samples/sample-conn.log"), "sample-conn.log",
                    bundled("samples/sample-conn.labels.csv"), "sample-conn.labels.csv", 0);
        } finally {
            facade.shutdown();
        }

        assertEquals(1693, report.flows(), "the fixture holds 1693 connections");
        assertEquals(1693, report.events());
        assertEquals(0, report.skipped());
        assertEquals(List.of(), report.problems());
        assertTrue(report.completed());
        assertTrue(report.labelsSource().endsWith("sample-conn.labels.csv"));
        assertEquals(37, report.unknownHosts(), "replay adds exactly 37 unknown hosts");

        Map<String, ImportService.LabelStat> stats = new LinkedHashMap<>();
        for (ImportService.LabelStat row : report.labels()) {
            stats.put(row.label(), row);
        }
        assertEquals(Set.of("NORMAL", "DOS_FLOOD", "PORT_SCAN", "NTP_HEALTH", "BEACONING",
                "BRUTE_FORCE", "LATERAL_MOVEMENT", "DATA_EXFIL", "NORMAL_TYPO", "NORMAL_BACKUP"),
                stats.keySet(), "the report carries one row per label in the file");

        assertTrue(stats.get("PORT_SCAN").alerts() >= 1, "PORT_SCAN must produce at least one alert");
        assertTrue(stats.get("BRUTE_FORCE").alerts() >= 1, "BRUTE_FORCE must produce at least one alert");
        assertTrue(stats.get("BEACONING").alerts() >= 1, "BEACONING must produce at least one alert");
        assertTrue(stats.get("LATERAL_MOVEMENT").alerts() >= 1, "LATERAL_MOVEMENT must produce at least one alert");
        assertTrue(stats.get("DATA_EXFIL").alerts() >= 1, "DATA_EXFIL must produce at least one alert");
        assertTrue(stats.get("DOS_FLOOD").alerts() >= 1, "DOS_FLOOD must produce at least one alert");

        assertEquals(0, stats.get("NTP_HEALTH").alerts(), "NTP_HEALTH must raise no alert at any severity");

        List<pk.ooad.ntd.domain.Alert> typoAlerts = alertsForLabel(delivered, stats, "NORMAL_TYPO");
        for (pk.ooad.ntd.domain.Alert a : typoAlerts) {
            assertTrue(a.getSeverity() == Severity.LOW,
                    "NORMAL_TYPO must not raise an alert at HIGH or above, got: " + a.getSeverity());
        }

        List<pk.ooad.ntd.domain.Alert> backupAlerts = alertsForLabel(delivered, stats, "NORMAL_BACKUP");
        for (pk.ooad.ntd.domain.Alert a : backupAlerts) {
            assertTrue(a.getSeverity() == Severity.LOW,
                    "NORMAL_BACKUP must not raise an alert at HIGH or above, got: " + a.getSeverity());
        }

        assertEquals(report.flows(), stats.values().stream().mapToLong(ImportService.LabelStat::flows).sum());
        assertEquals(report.alerts(), stats.values().stream().mapToLong(ImportService.LabelStat::alerts).sum(),
                "the per-label table accounts for every delivered alert");

        assertEquals(1248, stats.get("NORMAL").flows());
        assertEquals(300, stats.get("DOS_FLOOD").flows());
        assertEquals(40, stats.get("PORT_SCAN").flows());
        assertEquals(30, stats.get("NTP_HEALTH").flows());
        assertEquals(25, stats.get("BEACONING").flows());
        assertEquals(20, stats.get("BRUTE_FORCE").flows());
        assertEquals(16, stats.get("LATERAL_MOVEMENT").flows());
        assertEquals(8, stats.get("DATA_EXFIL").flows());
        assertEquals(5, stats.get("NORMAL_TYPO").flows());
        assertEquals(1, stats.get("NORMAL_BACKUP").flows());
    }

    private static List<pk.ooad.ntd.domain.Alert> alertsForLabel(
            List<pk.ooad.ntd.domain.Alert> all,
            Map<String, ImportService.LabelStat> stats,
            String label) {
        ImportService.LabelStat row = stats.get(label);
        if (row == null || row.alerts() == 0) {
            return List.of();
        }
        return new ArrayList<>(all.subList(Math.max(0, all.size() - (int) row.alerts()), all.size()));
    }
}
