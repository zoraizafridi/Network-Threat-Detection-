package pk.ooad.ntd.flows;

import java.time.Instant;

/**
 * Filter for {@link FlowRecorder#query(FlowQuery)}. A null field means "no
 * constraint", so {@link #all(int)} returns everything the recorder holds.
 *
 * @param srcIp         exact source address
 * @param dstIp         exact destination address
 * @param port          matches either the source or the destination port
 * @param from          inclusive lower bound on the flow end time
 * @param to            inclusive upper bound on the flow start time
 * @param limit         maximum rows returned; zero or less falls back to the
 *                      recorder's configured cap
 * @param includeActive whether flows that are still open are included
 */
public record FlowQuery(
        String srcIp,
        String dstIp,
        Integer port,
        Instant from,
        Instant to,
        int limit,
        boolean includeActive
) {
    public static FlowQuery all(int limit) {
        return new FlowQuery(null, null, null, null, null, limit, true);
    }

    public FlowQuery withLimit(int newLimit) {
        return new FlowQuery(srcIp, dstIp, port, from, to, newLimit, includeActive);
    }

    public FlowQuery withIncludeActive(boolean include) {
        return new FlowQuery(srcIp, dstIp, port, from, to, limit, include);
    }

    boolean matches(FlowRecord flow) {
        if (flow == null) {
            return false;
        }
        if (srcIp != null && !srcIp.equals(flow.srcIp())) {
            return false;
        }
        if (dstIp != null && !dstIp.equals(flow.dstIp())) {
            return false;
        }
        if (port != null && port != flow.srcPort() && port != flow.dstPort()) {
            return false;
        }
        if (from != null && flow.endTime() != null && flow.endTime().isBefore(from)) {
            return false;
        }
        if (to != null && flow.startTime() != null && flow.startTime().isAfter(to)) {
            return false;
        }
        return true;
    }
}
