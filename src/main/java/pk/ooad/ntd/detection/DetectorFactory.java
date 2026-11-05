package pk.ooad.ntd.detection;

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
}

