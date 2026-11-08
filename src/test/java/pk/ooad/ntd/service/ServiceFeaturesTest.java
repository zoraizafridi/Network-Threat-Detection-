package pk.ooad.ntd.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.detection.DetectionEngine;
import pk.ooad.ntd.domain.Admin;
import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.AuthenticationException;
import pk.ooad.ntd.domain.HighAlert;
import pk.ooad.ntd.domain.IncidentStatus;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.SecurityAnalyst;
import pk.ooad.ntd.domain.Server;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.domain.User;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServiceFeaturesTest {
    private Path configFile;

    @AfterEach
    void cleanup() throws IOException {
        EventLog.getInstance().clear();
        if (configFile != null) Files.deleteIfExists(configFile);
        if (configFile != null) ConfigManager.getInstance().reload();
        configFile = null;
    }

    @Test
    void riskScorerRaisesCapsDecaysAndResetsAssetRiskAndLinks() throws IOException {
        loadConfig("risk.cap=25\nrisk.compromiseThreshold=20\nrisk.decayPerTick=5\n");
        Network network = new Network();
        NetworkAsset target = new Server("target", "Target", "10.0.0.2", 2);
        NetworkAsset neighbor = new Server("neighbor", "Neighbor", "10.0.0.3", 2);
        Link link = new Link("target-link", target, neighbor, 1, 10);
        network.addAsset(target);
        network.addAsset(neighbor);
        network.addLink(link);
        RiskScorer scorer = new RiskScorer(network);

        scorer.onAlert(alert("source", target.getIp(), Severity.HIGH, "one"));
        assertEquals(20.0, target.getRiskScore());
        assertEquals(pk.ooad.ntd.domain.AssetStatus.COMPROMISED, target.getStatus());
        assertEquals(pk.ooad.ntd.domain.LinkStatus.COMPROMISED, link.getStatus());
        scorer.onAlert(alert("source", target.getIp(), Severity.HIGH, "two"));
        assertEquals(25.0, target.getRiskScore());
        scorer.onAlert(alert("source", "unknown", Severity.CRITICAL, "unknown"));
        assertEquals(25.0, target.getRiskScore());

        scorer.decay();
        assertEquals(20.0, target.getRiskScore());
        scorer.decay();
        assertEquals(15.0, target.getRiskScore());
        assertEquals(pk.ooad.ntd.domain.AssetStatus.SUSPICIOUS, target.getStatus());
        scorer.reset();
        assertEquals(0.0, target.getRiskScore());
        assertEquals(pk.ooad.ntd.domain.AssetStatus.NORMAL, target.getStatus());
        assertEquals(pk.ooad.ntd.domain.LinkStatus.NORMAL, link.getStatus());
        loadConfig("risk.cap=10\nrisk.compromiseThreshold=20\nrisk.decayPerTick=1\n");
        assertThrows(IllegalArgumentException.class, () -> new RiskScorer(network));
    }

    @Test
    void incidentsCorrelateBySourceWithinWindowAndClose() throws IOException {
        loadConfig("incident.correlationWindowSeconds=10\n");
        IncidentManager manager = new IncidentManager();
        manager.onAlert(alert("same", "10.0.0.1", Severity.LOW, "first"));
        manager.onAlert(alert("same", "10.0.0.2", Severity.HIGH, "at-boundary"));
        assertEquals(1, manager.getIncidents().size());
        Incident incident = manager.getIncidents().get(0);
        assertEquals(Severity.HIGH, incident.getHighestSeverity());
        assertTrue(incident.toString().contains("same"));
        incident.close();
        assertTrue(incident.toString().contains(IncidentStatus.CLOSED.name()));

        manager.onAlert(new HighAlert("late", Instant.parse("2026-01-01T00:00:11Z"), AttackType.PORT_SCAN,
                "same", "10.0.0.3", "test", "outside window"));
        assertEquals(2, manager.getIncidents().size());
        manager.reset();
        assertTrue(manager.getIncidents().isEmpty());
        assertThrows(NullPointerException.class, () -> manager.onAlert(null));
    }

    @Test
    void authenticationSOCAndAlertLoggingCoverNormalAndInvalidInputs() throws Exception {
        loadConfig("soc.defaultTeamCapacity=10\n");
        User analyst = new SecurityAnalyst("analyst", "secret");
        AuthService auth = new AuthService(List.of(analyst));
        assertEquals(analyst, auth.login("analyst", "secret"));
        assertThrows(AuthenticationException.class, () -> auth.login("analyst", "wrong"));
        assertThrows(AuthenticationException.class, () -> auth.login("missing", "secret"));
        assertThrows(AuthenticationException.class, () -> auth.login(null, "secret"));
        assertThrows(AuthenticationException.class, () -> new AuthService(null).login("nobody", "x"));

        DetectionEngine engine = new DetectionEngine(new LinkedBlockingQueue<>(), new AlertBus());
        SOC soc = new SOC(engine);
        AnalystTeam available = new AnalystTeam("team", "Team", Set.of(), 10, true);
        AnalystTeam unavailable = new AnalystTeam("offline", "Offline", Set.of(), 10, false);
        soc.addTeam(available);
        soc.addTeam(unavailable);
        soc.addTeam(available);
        soc.addTeam(null);
        assertEquals(List.of(available), soc.getAvailableTeams());

        Alert high = alert("source", "target", Severity.HIGH, "logged");
        new AlertLogger().onAlert(high);
        assertTrue(EventLog.getInstance().getEntries().get(0).contains("[WARN]"));
        new AlertLogger().onAlert(null);
        assertEquals(1, EventLog.getInstance().getEntries().size());
    }

    @Test
    void reportGeneratorBuildsAndExportsReportAndRejectsBadPaths() throws IOException {
        loadConfig("");
        Incident incident = new Incident("incident-1", alert("203.0.113.8", "target", Severity.HIGH, "test"));
        ReportGenerator generator = new ReportGenerator();
        Network network = new Network();
        network.addAsset(new Server("server", "Server", "target", 2));
        String report = generator.generate(List.of(incident), network, null);
        assertTrue(report.contains("Incident Response Report"));
        assertTrue(report.contains("incident-1"));
        assertTrue(report.contains("203.0.113.8"));
        Path output = Files.createTempFile("ntd-report", ".txt");
        try {
            generator.export(report, output.toString());
            assertEquals(report, Files.readString(output));
            assertThrows(IllegalArgumentException.class, () -> generator.export(null, output.toString()));
            assertThrows(IllegalArgumentException.class, () -> generator.export("x", " "));
        } finally {
            Files.deleteIfExists(output);
        }
        assertFalse(report.isBlank());
    }

    @Test
    void facadeLoginAndResetExposeOnlyServiceLevelOperations() throws IOException {
        loadConfig("risk.cap=100\nrisk.compromiseThreshold=60\nrisk.decayPerTick=1\nincident.correlationWindowSeconds=300\ndetection.cooldownSeconds=5\nsoc.defaultTeamCapacity=100\nauth.defaultUsername=admin\nauth.defaultPassword=admin\n");
        IncidentResponseFacade facade = new IncidentResponseFacade();
        assertEquals(Admin.class, facade.login("admin", "admin").getClass());
        assertThrows(IllegalArgumentException.class, () -> facade.login("admin", "bad"));
        facade.reset();
        assertTrue(facade.getIncidents().isEmpty());
        assertTrue(facade.getNetwork().getAssets().stream().allMatch(a -> a.getRiskScore() == 0.0));
    }

    private Alert alert(String source, String target, Severity severity, String description) {
        return new AlertFactory().create(severity, AttackType.PORT_SCAN, source, target,
                "test-detector", description, Instant.parse("2026-01-01T00:00:00Z"));
    }

    private void loadConfig(String contents) throws IOException {
        configFile = Files.createTempFile("ntd-service-config", ".properties");
        Files.writeString(configFile, contents);
        ConfigManager.getInstance().load(configFile.toString());
    }
}
