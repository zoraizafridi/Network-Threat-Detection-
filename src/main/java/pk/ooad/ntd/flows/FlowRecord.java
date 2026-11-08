package pk.ooad.ntd.flows;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * One connection record in the shape a NetFlow/IPFIX exporter would emit: a
 * five-tuple, directional byte counters, and a start/end pair.
 *
 * <p>Two fields are projections of the simulated feed rather than measurements,
 * and the caller can tell them apart:</p>
 * <ul>
 *   <li>{@code srcPort} is derived from the tuple because
 *       {@link pk.ooad.ntd.domain.NetworkEvent} only carries a destination port.
 *       See {@link FlowRecorder} for the derivation rule.</li>
 *   <li>{@code bytesIn} stays zero: the simulator emits unidirectional events
 *       and never reports reply traffic.</li>
 * </ul>
 *
 * <p>{@code flags} holds observation flags built from the aggregated events
 * ({@code OK} when every event succeeded, {@code FAILED} when any failed). The
 * feed does not expose TCP flags, so no SYN/ACK/RST value is ever invented.</p>
 *
 * <p>{@code ended} is false while the flow is still open. Open flows are
 * snapshots that grow as more events arrive.</p>
 */
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

    /** Elapsed time between the first and the last event of the flow. */
    public long durationMs() {
        if (startTime == null || endTime == null) {
            return 0L;
        }
        return Math.max(0L, Duration.between(startTime, endTime).toMillis());
    }
}
