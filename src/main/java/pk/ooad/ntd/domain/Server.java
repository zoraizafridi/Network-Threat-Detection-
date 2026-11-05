package pk.ooad.ntd.domain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Server extends NetworkAsset {
    private List<String> services;

    public Server(String id, String name, String ip, int criticality, List<String> services) {
        super(id, name, ip, AssetType.SERVER, criticality);
        this.services = services != null ? new ArrayList<>(services) : new ArrayList<>();
    }

    public Server(String id, String name, String ip, int criticality) {
        this(id, name, ip, criticality, Collections.emptyList());
    }

    @Override
    public double getDefaultRiskWeight() {
        return 1.5;
    }

    @Override
    public List<Integer> getTypicalPorts() {
        return List.of(22, 80, 443, 8080);
    }

    public List<String> getServices() {
        return Collections.unmodifiableList(services);
    }

    public void addService(String service) {
        if (service != null && !service.isBlank()) {
            this.services.add(service);
        }
    }
}

