package pk.ooad.ntd.domain;

import java.time.Instant;

public class HighAlert extends Alert {

    public HighAlert(String id, Instant timestamp, AttackType attackType,
                     String sourceIp, String targetIp, String detectorName, String description) {
        super(id, timestamp, Severity.HIGH, attackType, sourceIp, targetIp, detectorName, description);
    }

    @Override
    public double getRiskIncrement() {
        return 20.0;
    }
}
