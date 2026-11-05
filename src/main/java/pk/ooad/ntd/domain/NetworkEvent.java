package pk.ooad.ntd.domain;

import java.time.Instant;

public record NetworkEvent(
    long id,
    Instant timestamp,
    String sourceIp,
    String destIp,
    int port,
    long bytes,
    EventType type,
    boolean success,
    String payload
) {
}

