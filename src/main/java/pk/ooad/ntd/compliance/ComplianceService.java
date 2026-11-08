package pk.ooad.ntd.compliance;

import pk.ooad.ntd.containment.ContainmentService;
import pk.ooad.ntd.forensics.EvidenceExporter;
import pk.ooad.ntd.notify.NotificationService;
import pk.ooad.ntd.persistence.PersistenceService;
import pk.ooad.ntd.persistence.PersistenceStatus;
import pk.ooad.ntd.security.AuditLog;
import pk.ooad.ntd.util.ConfigManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class ComplianceService {

    public record Summary(
            boolean storeEnabled,
            String databasePath,
            int storedFlows,
            int storedAlerts,
            long droppedRows,
            int retentionMinutes,
            int sweepMinutes,
            int auditCapacity,
            int auditRecords,
            long auditDenied,
            long auditFailed,
            boolean notificationsEnabled,
            int notificationBacklog,
            boolean containmentEnabled,
            int containedSources,
            boolean forensicsEnabled,
            String evidenceDirectory) {
    }

    private final PersistenceService persistence;
    private final AuditLog audit;
    private final NotificationService notifications;
    private final ContainmentService containment;
    private final EvidenceExporter exporter;
    private final ConfigManager config;

    public record Control(String id, String title, String status, String evidence, boolean indicative) {
    }

    public static final String MAPPING_NOTE = "Indicative mapping to ISO/IEC 27001:2022 Annex A: "
            + "it describes what this deployment does and is not a certification or an audit opinion.";

    public ComplianceService(PersistenceService persistence, AuditLog audit,
                             NotificationService notifications, ContainmentService containment,
                             EvidenceExporter exporter, ConfigManager config) {
        this.persistence = Objects.requireNonNull(persistence, "persistence must not be null");
        this.audit = Objects.requireNonNull(audit, "audit must not be null");
        this.notifications = Objects.requireNonNull(notifications, "notifications must not be null");
        this.containment = Objects.requireNonNull(containment, "containment must not be null");
        this.exporter = Objects.requireNonNull(exporter, "exporter must not be null");
        this.config = Objects.requireNonNull(config, "config must not be null");
    }

    public Summary summary() {
        PersistenceStatus store = persistence.status();
        return new Summary(
                store.enabled(),
                store.databasePath(),
                store.flowRows(),
                store.alertRows(),
                store.droppedRows(),
                persistence.settings().retentionMinutes(),
                persistence.settings().sweepMinutes(),
                audit.getMaxRecords(),
                audit.size(),
                audit.deniedCount(),
                audit.failedCount(),
                notifications.status().enabled(),
                notifications.status().outboxSize(),
                containment.status().enabled(),
                containment.status().blocked(),
                exporter.isEnabled(),
                exporter.directory().toString());
    }

    public String retentionCutoff() {
        return java.time.Instant.now()
                .minus(java.time.Duration.ofMinutes(persistence.settings().retentionMinutes()))
                .toString();
    }

    public List<Control> controls() {
        PersistenceStatus store = persistence.status();
        int retention = persistence.settings().retentionMinutes();
        int sweep = persistence.settings().sweepMinutes();
        List<Control> controls = new ArrayList<>();
        controls.add(new Control("A.8.15", "Logging",
                audit.isEnabled() ? (store.enabled() ? "PASS" : "PARTIAL") : "FAIL",
                audit.isEnabled()
                        ? "audit trail holds " + audit.size() + " of " + audit.getMaxRecords()
                                + " entries" + (store.enabled() ? ", persisted" : ", memory only")
                        : "audit.enabled is false; privileged actions are not recorded",
                true));
        controls.add(new Control("A.8.16", "Monitoring activities",
                store.enabled() && store.alertRows() > 0 ? "PASS" : "PARTIAL",
                store.enabled()
                        ? store.alertRows() + " alerts retained; containment mode " + containment.status().mode()
                        : "detectors run continuously, but alerts live in a bounded ring until "
                                + "persistence.enabled is true",
                true));
        controls.add(new Control("A.5.25", "Assessment of security events",
                "PASS",
                "alerts are grouped into incidents and ordered kill chains are escalated with their timeline",
                true));
        controls.add(new Control("A.8.6", "Capacity management",
                "PASS",
                "flow ring, write-behind queues, outbox and alert buffer are bounded and count their drops ("
                        + store.droppedRows() + " dropped rows)",
                true));
        controls.add(new Control("A.8.10", "Information deletion",
                retention > 0 && sweep > 0 ? "PASS" : "FAIL",
                "retention " + retention + " minutes, sweep every " + sweep
                        + " minutes, last sweep removed " + persistence.lastSweptRows() + " rows",
                true));
        controls.add(new Control("A.8.11", "Data masking",
                notifications.settings().redact() ? "PASS" : "PARTIAL",
                notifications.settings().redact()
                        ? "notification bodies are redacted and truncated before delivery"
                        : "notifications.redact is false; captured text is delivered verbatim",
                true));
        controls.add(new Control("A.8.9", "Configuration management",
                "PASS",
                "every capability is a configuration key with a safe default, and the effective values are "
                        + "reported by the component that owns them",
                true));
        return controls;
    }

    public int configuredAuditCap() {
        return config.getInt("audit.maxRecords", 2000);
    }
}
