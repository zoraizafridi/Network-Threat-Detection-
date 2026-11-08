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
    String payload,
    boolean simulated
) {
    public NetworkEvent(long id, Instant timestamp, String sourceIp, String destIp, int port,
                        long bytes, EventType type, boolean success, String payload) {
        this(id, timestamp, sourceIp, destIp, port, bytes, type, success, payload, false);
    }
}
