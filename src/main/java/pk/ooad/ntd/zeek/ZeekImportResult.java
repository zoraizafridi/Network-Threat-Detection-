package pk.ooad.ntd.zeek;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Outcome of one import.
 *
 * <p>{@code skipped} lines are reported rather than silently swallowed: a field
 * that is missing from a Zeek log is a fact about the file, and pretending the
 * line was imported would inflate the counts an analyst relies on.</p>
 */
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
