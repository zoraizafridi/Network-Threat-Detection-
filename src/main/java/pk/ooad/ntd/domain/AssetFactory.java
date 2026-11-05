package pk.ooad.ntd.domain;

import java.util.Objects;

public class AssetFactory {
    public NetworkAsset create(AssetType type, String id, String name, String ip, int criticality) {
        Objects.requireNonNull(type, "AssetType must not be null");
        Objects.requireNonNull(id, "id must not be null");
        return switch (type) {
            case SERVER -> new Server(id, name, ip, criticality);
            case WORKSTATION -> new Workstation(id, name, ip, criticality);
            case ROUTER -> new Router(id, name, ip, criticality);
            case IOT_DEVICE -> new IoTDevice(id, name, ip, criticality);
        };
    }
}

