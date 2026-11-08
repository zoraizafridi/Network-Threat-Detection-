package pk.ooad.ntd.persistence;

import java.time.Instant;

public record ModelSummaryRecord(Instant trainedAt, String state, int samples, int clusters,
                                 double threshold) {
}
