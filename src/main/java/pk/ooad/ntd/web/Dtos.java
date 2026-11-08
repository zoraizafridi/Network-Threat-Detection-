package pk.ooad.ntd.web;

import java.util.List;
import java.util.Map;

public class Dtos {
    public record AssetDto(String id, String name, String ip, String type, int criticality,
                           double riskScore, String status) {
    }

    public record LinkDto(String id, String source, String target, double baseCost,
                          double bandwidth, String status) {
    }

    public record AlertDto(String id, String timestamp, String severity, String attackType,
                           String sourceIp, String targetIp, String detectorName, String description,
                           boolean simulated, int occurrences, String firstSeen, String lastSeen,
                           String status) {
        public AlertDto(String id, String timestamp, String severity, String attackType,
                        String sourceIp, String targetIp, String detectorName, String description) {
            this(id, timestamp, severity, attackType, sourceIp, targetIp, detectorName, description,
                    true, 1, timestamp, timestamp, "NEW");
        }

        public AlertDto(String id, String timestamp, String severity, String attackType,
                        String sourceIp, String targetIp, String detectorName, String description,
                        boolean simulated) {
            this(id, timestamp, severity, attackType, sourceIp, targetIp, detectorName, description,
                    simulated, 1, timestamp, timestamp, "NEW");
        }
    }

    public record IncidentDto(String id, String sourceIp, String status, String openedAt,
                              List<AlertDto> alerts) {
    }

    public record FlowDto(String id, String srcIp, String dstIp, int srcPort, int dstPort,
                          String protocol, long bytesOut, long bytesIn, long packets,
                          String startTime, String endTime, long durationMs, List<String> flags,
                          String label, boolean simulated, boolean ended) {
    }

    public record PlanDto(Map<String, Object> backbone, Map<String, Object> assignment) {
    }

    public record StateDto(boolean running, boolean autoMode, Map<String, String> user,
                           int alertCount, int incidentCount) {
    }

    private Dtos() {
    }
}
