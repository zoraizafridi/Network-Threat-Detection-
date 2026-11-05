package pk.ooad.ntd.domain;

import java.time.Instant;

public class LowAlert extends Alert {

    public LowAlert(String id, Instant timestamp, AttackType attackType,
                    String sourceIp, String targetIp, String detectorName, String description) {
        super(id, timestamp, Severity.LOW, attackType, sourceIp, targetIp, detectorName, description);
    }

    @Override
    public double getRiskIncrement() {
        return 5.0;
    }
}

