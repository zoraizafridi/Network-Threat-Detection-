package pk.ooad.ntd.persistence;

import java.time.Instant;

public record NotificationRecord(String id, Instant timestamp, String severity, String attackType,
                                 String sourceIp, String targetIp, String summary, String channel) {
}
