package pk.ooad.ntd.zeek;

import java.time.Instant;
import java.util.List;
import java.util.Set;

public record ZeekImportResult(
        String source,
        long linesRead,
        long flowsParsed,
        long skipped,
        Instant firstTimestamp,
        Instant lastTimestamp,
        Set<String> hosts,
        List<String> problems,
        List<pk.ooad.ntd.flows.FlowRecord> records) {

    public ZeekImportResult {
        hosts = hosts == null ? Set.of() : Set.copyOf(hosts);
        problems = problems == null ? List.of() : List.copyOf(problems);
        records = records == null ? List.of() : List.copyOf(records);
    }

    public String summary() {
        return source + ": " + flowsParsed + " flows from " + linesRead + " lines, "
                + skipped + " skipped, " + hosts.size() + " hosts"
                + (firstTimestamp == null ? "" : ", " + firstTimestamp + " to " + lastTimestamp);
    }
}
