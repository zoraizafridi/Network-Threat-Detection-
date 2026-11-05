package pk.ooad.ntd.domain;

import java.time.Instant;

public class CriticalAlert extends Alert {

    public CriticalAlert(String id, Instant timestamp, AttackType attackType,
                         String sourceIp, String targetIp, String detectorName, String description) {
        super(id, timestamp, Severity.CRITICAL, attackType, sourceIp, targetIp, detectorName, description);
    }

    @Override
    public double getRiskIncrement() {
        return 50.0;
    }
}

