package pk.ooad.ntd.persistence;

import java.time.Instant;

public record ManifestRecord(String directory, Instant createdAt, int files, long bytes,
                             String manifestHash) {
}
