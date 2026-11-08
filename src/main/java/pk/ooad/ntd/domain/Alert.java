package pk.ooad.ntd.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public abstract class Alert {
    private final String id;
    private final Instant timestamp;
    private final Severity severity;
    private final AttackType attackType;
    private final String sourceIp;
    private final String targetIp;
    private final String detectorName;
    private final String description;
    private final AtomicInteger occurrences = new AtomicInteger(1);
    private volatile Instant firstSeen;
    private volatile Instant lastSeen;
    private volatile AlertStatus status = AlertStatus.NEW;
    private boolean simulated;

    protected Alert(String id, Instant timestamp, Severity severity, AttackType attackType,
                    String sourceIp, String targetIp, String detectorName, String description) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp must not be null");
        this.severity = Objects.requireNonNull(severity, "severity must not be null");
        this.attackType = Objects.requireNonNull(attackType, "attackType must not be null");
        this.sourceIp = sourceIp != null ? sourceIp : "";
        this.targetIp = targetIp != null ? targetIp : "";
        this.detectorName = detectorName != null ? detectorName : "";
        this.description = description != null ? description : "";
        this.firstSeen = this.timestamp;
        this.lastSeen = this.timestamp;
    }

    public abstract double getRiskIncrement();

    public String getId() {
        return id;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public Severity getSeverity() {
        return severity;
    }

    public AttackType getAttackType() {
        return attackType;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getTargetIp() {
        return targetIp;
    }

    public String getDetectorName() {
        return detectorName;
    }

    public String getDescription() {
        return description;
    }

    public boolean isSimulated() {
        return simulated;
    }

    public Alert markSimulated(boolean simulated) {
        this.simulated = simulated;
        return this;
    }

    public int getOccurrences() {
        return occurrences.get();
    }

    public Instant getFirstSeen() {
        return firstSeen;
    }

    public Instant getLastSeen() {
        return lastSeen;
    }

    public AlertStatus getStatus() {
        return status;
    }

    public int fold(Instant at) {
        int count = occurrences.incrementAndGet();
        if (at != null) {
            Instant last = lastSeen;
            if (last == null || at.isAfter(last)) {
                lastSeen = at;
            }
            Instant first = firstSeen;
            if (first == null || at.isBefore(first)) {
                firstSeen = at;
            }
        }
        return count;
    }

    public boolean moveTo(AlertStatus next) {
        AlertStatus current = status;
        if (!current.canMoveTo(next)) {
            return false;
        }
        status = next;
        return true;
    }

    public Alert restore(int occurrences, Instant firstSeen, Instant lastSeen, AlertStatus status) {
        this.occurrences.set(Math.max(1, occurrences));
        this.firstSeen = firstSeen != null ? firstSeen : timestamp;
        this.lastSeen = lastSeen != null ? lastSeen : timestamp;
        this.status = status != null ? status : AlertStatus.NEW;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Alert alert = (Alert) o;
        return Objects.equals(id, alert.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "id='" + id + '\'' +
                ", timestamp=" + timestamp +
                ", severity=" + severity +
                ", attackType=" + attackType +
                ", sourceIp='" + sourceIp + '\'' +
                ", targetIp='" + targetIp + '\'' +
                ", detectorName='" + detectorName + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
