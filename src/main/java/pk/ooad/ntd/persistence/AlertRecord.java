package pk.ooad.ntd.persistence;

import pk.ooad.ntd.domain.Alert;

import java.time.Instant;

/**
 * A stored alert as the durable table keeps it.
 *
 * <p>Severity and attack type stay strings on purpose. {@code Alert} is an
 * abstract class with three concrete subclasses, and re-creating a subclass from
 * a row would mean inventing state the original never had. A row is a record of
 * what was raised, not a live alert object.</p>
 */
public record AlertRecord(
        String id,
        Instant timestamp,
        String severity,
        String attackType,
        String sourceIp,
        String targetIp,
        String detector,
        String description,
        boolean simulated) {

    /** Projects a live alert onto the columns the store and the exporter use. */
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
                alert.isSimulated());
    }
}
