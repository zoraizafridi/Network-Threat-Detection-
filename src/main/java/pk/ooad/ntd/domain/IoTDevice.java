package pk.ooad.ntd.domain;

import java.util.List;

public class IoTDevice extends NetworkAsset {
    private String firmwareVersion;
    private boolean defaultCredentials;

    public IoTDevice(String id, String name, String ip, int criticality, String firmwareVersion, boolean defaultCredentials) {
        super(id, name, ip, AssetType.IOT_DEVICE, criticality);
        this.firmwareVersion = firmwareVersion != null ? firmwareVersion : "1.0";
        this.defaultCredentials = defaultCredentials;
    }

    public IoTDevice(String id, String name, String ip, int criticality) {
        this(id, name, ip, criticality, "1.0", false);
    }

    @Override
    public double getDefaultRiskWeight() {
        return 0.8;
    }

    @Override
    public List<Integer> getTypicalPorts() {
        return List.of(23, 80, 554, 1883);
    }

    public String getFirmwareVersion() {
        return firmwareVersion;
    }

    public void setFirmwareVersion(String firmwareVersion) {
        this.firmwareVersion = firmwareVersion != null ? firmwareVersion : "1.0";
    }

    public boolean hasDefaultCredentials() {
        return defaultCredentials;
    }

    public boolean isDefaultCredentials() {
        return defaultCredentials;
    }

    public void setDefaultCredentials(boolean defaultCredentials) {
        this.defaultCredentials = defaultCredentials;
    }
}

