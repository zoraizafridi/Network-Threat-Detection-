package pk.ooad.ntd.domain;

import java.util.List;

public class Router extends NetworkAsset {
    private int interfaceCount;

    public Router(String id, String name, String ip, int criticality, int interfaceCount) {
        super(id, name, ip, AssetType.ROUTER, criticality);
        this.interfaceCount = interfaceCount;
    }

    public Router(String id, String name, String ip, int criticality) {
        this(id, name, ip, criticality, 4);
    }

    @Override
    public double getDefaultRiskWeight() {
        return 1.2;
    }

    @Override
    public List<Integer> getTypicalPorts() {
        return List.of(22, 23, 80, 161);
    }

    public int getInterfaceCount() {
        return interfaceCount;
    }

    public void setInterfaceCount(int interfaceCount) {
        this.interfaceCount = interfaceCount;
    }
}

