package pk.ooad.ntd.flows;

import java.time.Instant;

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
