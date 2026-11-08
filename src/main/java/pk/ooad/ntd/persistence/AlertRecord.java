package pk.ooad.ntd.persistence;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertStatus;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.CriticalAlert;
import pk.ooad.ntd.domain.HighAlert;
import pk.ooad.ntd.domain.LowAlert;
import pk.ooad.ntd.domain.Severity;

import java.time.Instant;

public record AlertRecord(
        String id,
        Instant timestamp,
        String severity,
        String attackType,
        String sourceIp,
        String targetIp,
        String detector,
        String description,
        boolean simulated,
        int occurrences,
        Instant firstSeen,
        Instant lastSeen,
        String status) {

    public AlertRecord(String id, Instant timestamp, String severity, String attackType, String sourceIp,
                       String targetIp, String detector, String description, boolean simulated) {
        this(id, timestamp, severity, attackType, sourceIp, targetIp, detector, description, simulated,
                1, timestamp, timestamp, AlertStatus.NEW.name());
    }

    public static AlertRecord from(Alert alert) {
        return new AlertRecord(
                alert.getId(),
                alert.getTimestamp(),
                alert.getSeverity() == null ? "" : alert.getSeverity().name(),
                alert.getAttackType() == null ? "" : alert.getAttackType().name(),
                alert.getSourceIp(),
                alert.getTargetIp(),
                alert.getDetectorName(),
                alert.getDescription(),
                alert.isSimulated(),
                alert.getOccurrences(),
                alert.getFirstSeen(),
                alert.getLastSeen(),
                alert.getStatus().name());
    }

    public Alert toAlert() {
        if (id == null || timestamp == null) {
            return null;
        }
        Severity level;
        AttackType type;
        try {
            level = Severity.valueOf(severity);
            type = AttackType.valueOf(attackType);
        } catch (IllegalArgumentException | NullPointerException ex) {
            return null;
        }
        Alert alert = switch (level) {
            case LOW -> new LowAlert(id, timestamp, type, sourceIp, targetIp, detector, description);
            case HIGH -> new HighAlert(id, timestamp, type, sourceIp, targetIp, detector, description);
            case CRITICAL -> new CriticalAlert(id, timestamp, type, sourceIp, targetIp, detector, description);
        };
        alert.restore(occurrences, firstSeen, lastSeen, AlertStatus.parse(status));
        return alert.markSimulated(simulated);
    }
}
