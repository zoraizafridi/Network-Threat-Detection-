package pk.ooad.ntd.domain;

import java.util.List;
import java.util.Objects;

public abstract class NetworkAsset {
    private final String id;
    private String name;
    private String ip;
    private final AssetType type;
    private int criticality;
    private double riskScore;
    private AssetStatus status;

    protected NetworkAsset(String id, String name, String ip, AssetType type, int criticality) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.name = name != null ? name : "";
        this.ip = ip != null ? ip : "";
        this.type = Objects.requireNonNull(type, "type must not be null");
        this.criticality = criticality;
        this.riskScore = 0.0;
        this.status = AssetStatus.NORMAL;
    }

    public void addRisk(double delta) {
        this.riskScore = Math.max(0.0, Math.min(100.0, this.riskScore + delta));
    }

    public void setStatus(AssetStatus s) {
        this.status = Objects.requireNonNull(s, "AssetStatus must not be null");
    }

    public void resetRisk() {
        this.riskScore = 0.0;
    }

    public abstract double getDefaultRiskWeight();

    public abstract List<Integer> getTypicalPorts();

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name : "";
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip != null ? ip : "";
    }

    public AssetType getType() {
        return type;
    }

    public int getCriticality() {
        return criticality;
    }

    public void setCriticality(int criticality) {
        this.criticality = criticality;
    }

    public double getRiskScore() {
        return riskScore;
    }

    public AssetStatus getStatus() {
        return status;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NetworkAsset that = (NetworkAsset) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", ip='" + ip + '\'' +
                ", type=" + type +
                ", criticality=" + criticality +
                ", riskScore=" + riskScore +
                ", status=" + status +
                '}';
    }
}
