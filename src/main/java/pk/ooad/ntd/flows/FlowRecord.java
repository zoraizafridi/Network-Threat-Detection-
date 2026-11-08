package pk.ooad.ntd.flows;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

public record FlowRecord(
        String id,
        String srcIp,
        String dstIp,
        int srcPort,
        int dstPort,
        String protocol,
        long bytesOut,
        long bytesIn,
        long packets,
        Instant startTime,
        Instant endTime,
        List<String> flags,
        String label,
        boolean simulated,
        boolean ended
) {
    public FlowRecord {
        flags = flags == null ? List.of() : List.copyOf(flags);
    }

    public long durationMs() {
        if (startTime == null || endTime == null) {
            return 0L;
        }
        return Math.max(0L, Duration.between(startTime, endTime).toMillis());
    }
}
