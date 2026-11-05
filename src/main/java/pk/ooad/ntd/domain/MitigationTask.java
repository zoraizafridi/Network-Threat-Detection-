package pk.ooad.ntd.domain;

import java.util.Objects;

public class MitigationTask {
    private final String id;
    private final NetworkAsset target;
    private final int value;
    private final int cost;
    private final String requiredSkill;

    public MitigationTask(String id, NetworkAsset target, int value, int cost, String requiredSkill) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.target = Objects.requireNonNull(target, "target must not be null");
        this.value = value;
        this.cost = cost;
        this.requiredSkill = requiredSkill != null ? requiredSkill : "";
    }

    public String getId() {
        return id;
    }

    public NetworkAsset getTarget() {
        return target;
    }

    public int getValue() {
        return value;
    }

    public int getCost() {
        return cost;
    }

    public String getRequiredSkill() {
        return requiredSkill;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MitigationTask that = (MitigationTask) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "MitigationTask{" +
                "id='" + id + '\'' +
                ", target=" + target.getId() +
                ", value=" + value +
                ", cost=" + cost +
                ", requiredSkill='" + requiredSkill + '\'' +
                '}';
    }
}

