package pk.ooad.ntd.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.persistence.AuditRecord;
import pk.ooad.ntd.persistence.ContainmentRecord;
import pk.ooad.ntd.persistence.IncidentRecord;
import pk.ooad.ntd.persistence.ModelSummaryRecord;
import pk.ooad.ntd.persistence.PersistenceService;
import pk.ooad.ntd.persistence.PersistenceSettings;
import pk.ooad.ntd.util.ConfigManager;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RestoreTest {

    @TempDir
    Path temp;

    @AfterEach
    void clearOverrides() {
        System.clearProperty("ntd.persistence.enabled");
        System.clearProperty("ntd.persistence.dir");
        System.clearProperty("ntd.persistence.file");
        ConfigManager.getInstance().reload();
    }

    @Test
    @DisplayName("The next start brings back alerts, incidents, blocks, audit rows and the model summary")
    void restoreRebuildsWhatTheStoreHolds() {
        Path database = temp.resolve("restore.db");
        System.setProperty("ntd.persistence.enabled", "true");
        System.setProperty("ntd.persistence.dir", temp.toString());
        System.setProperty("ntd.persistence.file", "restore.db");

        Instant now = Instant.now();
        Alert alert = new AlertFactory().create(Severity.HIGH, AttackType.PORT_SCAN,
                "203.0.113.9", "10.0.0.4", "SignatureDetector", "scan", now);
        try (PersistenceService store = new PersistenceService(
                PersistenceSettings.disabled().withEnabled(true).withDatabasePath(database))) {
            assertTrue(store.isEnabled(), "the first store must open");
            store.onAlert(alert);
            store.recordIncident(new IncidentRecord("incident-1", now, "203.0.113.9",
                    "OPEN", "HIGH", List.of(alert.getId())));
            store.recordContainment(new ContainmentRecord("203.0.113.9", now,
                    now.plusSeconds(3_600), "repeat offender", "admin", true, false));
            store.recordAudit(new AuditRecord(now, "admin", "containment.mode", "203.0.113.9",
                    "ALLOWED", "blocked"));
            store.recordModelSummary(new ModelSummaryRecord(now, "ready", 120, 4, 0.91));
            assertTrue(store.flush(5_000));
        }

        IncidentResponseFacade facade = new IncidentResponseFacade(TopologyLoader.loadSample(), 42L);
        try {
            IncidentResponseFacade.RestoreReport report = facade.restore();

            assertTrue(report.durable(), "the facade must open the same file the store wrote");
            assertEquals(2, report.schemaVersion());
            assertEquals(1, report.alerts());
            assertEquals(1, report.incidents());
            assertEquals(1, report.containment());
            assertEquals(1, report.audit());
            assertTrue(report.model(), "a stored model summary is reported");

            assertEquals(List.of(alert.getId()),
                    facade.restoredAlerts().stream().map(Alert::getId).toList());
            assertEquals(1, facade.getIncidents().size());
            assertEquals("incident-1", facade.getIncidents().get(0).getId());
            assertEquals(List.of(alert.getId()), facade.getIncidents().get(0).alertIds());
            assertEquals(1, facade.getAuditLog().size());
        } finally {
            facade.shutdown();
        }
    }
}
