package pk.ooad.ntd.persistence;

import java.time.Instant;
import java.util.List;

public record IncidentRecord(String id, Instant openedAt, String sourceIp, String status,
                             String highestSeverity, List<String> alertIds) {
}
