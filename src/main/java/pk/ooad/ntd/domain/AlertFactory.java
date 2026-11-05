package pk.ooad.ntd.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public class AlertFactory {

    public Alert create(Severity sev, AttackType type, String src, String dst,
                        String detector, String desc, Instant time) {
        Objects.requireNonNull(sev, "Severity must not be null");
        Objects.requireNonNull(type, "AttackType must not be null");
        Instant timestamp = time != null ? time : Instant.now();
        String id = UUID.randomUUID().toString();

        return switch (sev) {
            case LOW -> new LowAlert(id, timestamp, type, src, dst, detector, desc);
            case HIGH -> new HighAlert(id, timestamp, type, src, dst, detector, desc);
            case CRITICAL -> new CriticalAlert(id, timestamp, type, src, dst, detector, desc);
        };
    }
}

