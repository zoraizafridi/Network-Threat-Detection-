package pk.ooad.ntd.compliance;

import pk.ooad.ntd.containment.ContainmentService;
import pk.ooad.ntd.forensics.EvidenceExporter;
import pk.ooad.ntd.notify.NotificationService;
import pk.ooad.ntd.persistence.PersistenceService;
import pk.ooad.ntd.persistence.PersistenceStatus;
import pk.ooad.ntd.security.AuditLog;
import pk.ooad.ntd.util.ConfigManager;

import java.util.Objects;

/**
 * Answers the questions an auditor asks about this deployment: how long records
 * survive, what is kept about privileged actions, and which capabilities are
 * actually switched on.
 *
 * <p>Every number here is read from the component that owns it. A summary that
 * restated configured values would report intent; this one reports state, which
 * is the only version worth signing.</p>
 */
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

    /** The retention cutoff being enforced right now, as an ISO instant string. */
    public String retentionCutoff() {
        return java.time.Instant.now()
                .minus(java.time.Duration.ofMinutes(persistence.settings().retentionMinutes()))
                .toString();
    }

    /** Whatever the operator set for the audit cap, reported where it is read. */
    public int configuredAuditCap() {
        return config.getInt("audit.maxRecords", 2000);
    }
}
