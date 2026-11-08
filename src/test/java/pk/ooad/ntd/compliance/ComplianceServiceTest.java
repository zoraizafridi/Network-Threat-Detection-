package pk.ooad.ntd.compliance;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pk.ooad.ntd.containment.ContainmentService;
import pk.ooad.ntd.forensics.EvidenceExporter;
import pk.ooad.ntd.notify.NotificationService;
import pk.ooad.ntd.persistence.PersistenceService;
import pk.ooad.ntd.persistence.PersistenceSettings;
import pk.ooad.ntd.security.AuditLog;
import pk.ooad.ntd.util.ConfigManager;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ComplianceServiceTest {

    @TempDir
    Path temp;

    private ComplianceService service(PersistenceService persistence, AuditLog audit) {
        ConfigManager config = ConfigManager.getInstance();
        return new ComplianceService(persistence, audit,
                new NotificationService(),
                new ContainmentService(Clock.systemUTC(), config),
                new EvidenceExporter(false, temp.resolve("evidence"), 10, 10),
                config);
    }

    @Test
    @DisplayName("The summary reports the state of every owning component")
    void summaryReflectsComponents() {
        AuditLog audit = new AuditLog(true, 50);
        audit.record("admin", "auth.login", "127.0.0.1", AuditLog.Outcome.ALLOWED, "Admin");
        audit.record("viewer", "containment.block", "10.0.0.5", AuditLog.Outcome.DENIED, "role Viewer");
        audit.record("admin", "evidence.export", "evidence", AuditLog.Outcome.FAILED, "disabled");

        try (PersistenceService persistence = new PersistenceService(PersistenceSettings.disabled())) {
            ComplianceService service = service(persistence, audit);
            ComplianceService.Summary summary = service.summary();

            assertFalse(summary.storeEnabled());
            assertTrue(summary.databasePath().endsWith("ntd.db"));
            assertEquals(0, summary.storedFlows());
            assertEquals(0, summary.storedAlerts());
            assertEquals(0, summary.droppedRows());
            assertEquals(1_440, summary.retentionMinutes());
            assertEquals(5, summary.sweepMinutes());
            assertEquals(50, summary.auditCapacity());
            assertEquals(3, summary.auditRecords());
            assertEquals(1, summary.auditDenied());
            assertEquals(1, summary.auditFailed());
            assertFalse(summary.notificationsEnabled());
            assertEquals(0, summary.notificationBacklog());
            assertFalse(summary.containmentEnabled());
            assertEquals(0, summary.containedSources());
            assertFalse(summary.forensicsEnabled());
            assertEquals(temp.resolve("evidence").toString(), summary.evidenceDirectory());

            Instant cutoff = Instant.parse(service.retentionCutoff());
            assertTrue(cutoff.isBefore(Instant.now()));
            assertTrue(service.configuredAuditCap() >= 1);
        }
    }

    @Test
    @DisplayName("An enabled store reports real row counts")
    void summaryReportsStoredRows() {
        PersistenceSettings settings = PersistenceSettings.disabled()
                .withEnabled(true)
                .withDatabasePath(temp.resolve("data/ntd.db"))
                .withRetentionMinutes(120);
        AuditLog audit = new AuditLog(true, 10);
        try (PersistenceService persistence = new PersistenceService(settings)) {
            Instant now = Instant.now();
            persistence.importFlows(List.of(
                    new pk.ooad.ntd.flows.FlowRecord("f1", "10.0.0.5", "10.0.0.9", 40_000, 443, "TCP",
                            100, 0, 1, now, now.plusSeconds(1), List.of("OK"), "REQUEST", false, true),
                    new pk.ooad.ntd.flows.FlowRecord("f2", "10.0.0.6", "10.0.0.9", 40_001, 443, "TCP",
                            200, 0, 2, now, now.plusSeconds(1), List.of("OK"), "REQUEST", false, true)));
            persistence.onAlert(new pk.ooad.ntd.domain.AlertFactory().create(
                    pk.ooad.ntd.domain.Severity.HIGH, pk.ooad.ntd.domain.AttackType.PORT_SCAN,
                    "10.0.0.6", "10.0.0.9", "PortScanDetector", "scan", now));
            assertTrue(persistence.flush(5_000));

            ComplianceService service = service(persistence, audit);
            ComplianceService.Summary summary = service.summary();
            assertTrue(summary.storeEnabled());
            assertEquals(2, summary.storedFlows());
            assertEquals(1, summary.storedAlerts());
            assertEquals(0, summary.droppedRows());
            assertEquals(120, summary.retentionMinutes());
            assertEquals(0, summary.auditRecords());
        }
    }

    @Test
    @DisplayName("A disabled audit log reports zero records but keeps its capacity")
    void disabledAuditStillReportsCapacity() {
        try (PersistenceService persistence = new PersistenceService(PersistenceSettings.disabled())) {
            ComplianceService service = service(persistence, new AuditLog(false, 25));
            ComplianceService.Summary summary = service.summary();
            assertEquals(25, summary.auditCapacity());
            assertEquals(0, summary.auditRecords());
            assertEquals(0, summary.auditDenied());
            assertEquals(0, summary.auditFailed());
        }
    }
}
