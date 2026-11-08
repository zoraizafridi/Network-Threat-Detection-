package pk.ooad.ntd.persistence;

import java.time.Instant;

public record AuditRecord(Instant timestamp, String actor, String action, String target,
                          String outcome, String detail) {
}
