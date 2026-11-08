package pk.ooad.ntd.persistence;

import java.time.Instant;

public record ContainmentRecord(String ip, Instant blockedAt, Instant expiresAt, String reason,
                                String actor, boolean automatic, boolean released) {
}
