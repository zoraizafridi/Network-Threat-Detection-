package pk.ooad.ntd.detection;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class DetectorFactory {

    public Detector create(String name) {
        Objects.requireNonNull(name, "name must not be null");
        String lower = name.toLowerCase();
        if (lower.contains("signature")) {
            return new SignatureDetector();
        } else if (lower.contains("rate") || lower.contains("bruteforce")) {
            return new RateThresholdDetector();
        } else if (lower.contains("port") || lower.contains("scan")) {
            return new PortScanDetector();
        } else if (lower.contains("anomaly")) {
            return new AnomalyDetector();
        } else if (lower.contains("intel")) {
            return new ThreatIntelDetector();
        } else if (lower.contains("beacon")) {
            return new BeaconingDetector();
        } else if (lower.contains("exfil")) {
            return new DataExfilDetector();
        } else if (lower.contains("lateral")) {
            return new LateralMovementDetector();
        } else if (lower.contains("flood")) {
            return new FloodDetector();
        }
        throw new IllegalArgumentException("Unknown detector name: " + name);
    }

    public List<Detector> createAll() {
        return List.of(
            new SignatureDetector(),
            new RateThresholdDetector(),
            new PortScanDetector(),
            new AnomalyDetector()
        );
    }

    public List<Detector> createNdr() {
        List<Detector> detectors = new ArrayList<>();
        detectors.add(new ThreatIntelDetector());
        detectors.add(new BeaconingDetector());
        detectors.add(new DataExfilDetector());
        detectors.add(new LateralMovementDetector());
        detectors.add(new FloodDetector());
        return List.copyOf(detectors);
    }
}
