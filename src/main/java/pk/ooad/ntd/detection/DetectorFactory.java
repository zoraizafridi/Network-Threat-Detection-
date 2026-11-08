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
        }
        throw new IllegalArgumentException("Unknown detector name: " + name);
    }

    /**
     * The four core detectors. The contract of this method is fixed: existing
     * tests and callers rely on exactly these four, so new detectors are added
     * through {@link #createNdr()} instead of silently changing this list.
     */
    public List<Detector> createAll() {
        return List.of(
            new SignatureDetector(),
            new RateThresholdDetector(),
            new PortScanDetector(),
            new AnomalyDetector()
        );
    }

    /**
     * The network detection and response detectors. Each one reads its own
     * {@code enabled} flag and does nothing when that flag is off, so the
     * pipeline can carry them unconditionally while the default behaviour stays
     * exactly as it was.
     */
    public List<Detector> createNdr() {
        List<Detector> detectors = new ArrayList<>();
        detectors.add(new ThreatIntelDetector());
        detectors.add(new BeaconingDetector());
        detectors.add(new DataExfilDetector());
        detectors.add(new LateralMovementDetector());
        return List.copyOf(detectors);
    }
}

