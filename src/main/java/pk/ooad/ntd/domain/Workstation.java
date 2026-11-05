package pk.ooad.ntd.domain;

import java.util.List;

public class Workstation extends NetworkAsset {
    private String owner;

    public Workstation(String id, String name, String ip, int criticality, String owner) {
        super(id, name, ip, AssetType.WORKSTATION, criticality);
        this.owner = owner != null ? owner : "";
    }

    public Workstation(String id, String name, String ip, int criticality) {
        this(id, name, ip, criticality, "");
    }

    @Override
    public double getDefaultRiskWeight() {
        return 1.0;
    }

    @Override
    public List<Integer> getTypicalPorts() {
        return List.of(135, 139, 445, 3389);
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner != null ? owner : "";
    }
}

