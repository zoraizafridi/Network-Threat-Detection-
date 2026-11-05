package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.AttackType;

import java.time.Instant;
import java.util.Objects;

public class AttackRecord {
    private final AttackType type;
    private final String source;
    private final String target;
    private final Instant startTime;

    public AttackRecord(AttackType type, String source, String target, Instant startTime) {
        this.type = Objects.requireNonNull(type, "type must not be null");
        this.source = source != null ? source : "";
        this.target = target != null ? target : "";
        this.startTime = Objects.requireNonNull(startTime, "startTime must not be null");
    }

    public AttackType getType() {
        return type;
    }

    public String getSource() {
        return source;
    }

    public String getTarget() {
        return target;
    }

    public Instant getStartTime() {
        return startTime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        AttackRecord that = (AttackRecord) o;
        return type == that.type &&
                Objects.equals(source, that.source) &&
                Objects.equals(target, that.target) &&
                Objects.equals(startTime, that.startTime);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, source, target, startTime);
    }

    @Override
    public String toString() {
        return "AttackRecord{" +
                "type=" + type +
                ", source='" + source + '\'' +
                ", target='" + target + '\'' +
                ", startTime=" + startTime +
                '}';
    }
}
