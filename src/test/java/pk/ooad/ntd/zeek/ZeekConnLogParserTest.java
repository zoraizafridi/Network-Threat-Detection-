package pk.ooad.ntd.zeek;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pk.ooad.ntd.flows.FlowRecord;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZeekConnLogParserTest {

    private static final String LOG = """
            #separator \\x09
            #fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state
            1756900800.000000\tC1\t10.0.0.5\t51515\t203.0.113.9\t443\ttcp\tssl\t1.500000\t1200\t3400\tSF
            1756900860.000000\tC2\t10.0.0.6\t51516\t203.0.113.9\t53\tudp\tdns\t0.100000\t80\t120\tS0
            """;

    @TempDir
    Path temp;

    @Test
    @DisplayName("Header-driven parse keeps real ports, protocol, state and label")
    void parsesHeaderDrivenLog() {
        ZeekImportResult result = new ZeekConnLogParser().parse(LOG, "conn.log");

        assertEquals("conn.log", result.source());
        assertEquals(2, result.linesRead());
        assertEquals(2, result.flowsParsed());
        assertEquals(0, result.skipped());
        assertEquals(3, result.hosts().size());
        assertEquals(Instant.ofEpochSecond(1_756_900_800L), result.firstTimestamp());
        assertEquals(Instant.ofEpochSecond(1_756_900_860L), result.lastTimestamp());

        FlowRecord first = result.records().get(0);
        assertEquals("C1", first.id());
        assertEquals("10.0.0.5", first.srcIp());
        assertEquals("203.0.113.9", first.dstIp());
        assertEquals(51_515, first.srcPort());
        assertEquals(443, first.dstPort());
        assertEquals("TCP", first.protocol());
        assertEquals(1_200, first.bytesOut());
        assertEquals(3_400, first.bytesIn());
        assertEquals(List.of("SF"), first.flags());
        assertEquals("SSL", first.label());
        assertEquals(1_500, first.durationMs());
        assertTrue(first.ended());
        assertEquals(1_756_900_800_000L, first.startTime().toEpochMilli());

        FlowRecord second = result.records().get(1);
        assertEquals("UDP", second.protocol());
        assertEquals("DNS", second.label());
        assertEquals(List.of("S0"), second.flags());
        assertTrue(result.summary().contains("2 flows from 2 lines"));
    }

    @Test
    @DisplayName("Rows without an address or port are skipped and counted")
    void skipsIncompleteRows() {
        String log = """
                #fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto
                1756900800.0\tC1\t-\t51515\t203.0.113.9\t443\ttcp
                1756900801.0\tC2\t10.0.0.5\t-\t203.0.113.9\t443\ttcp
                1756900802.0\tC3\t10.0.0.5\t51517\t203.0.113.9\t443\ttcp
                """;
        ZeekImportResult result = new ZeekConnLogParser().parse(log, "partial.log");
        assertEquals(3, result.linesRead());
        assertEquals(1, result.flowsParsed());
        assertEquals(2, result.skipped());
        assertEquals("C3", result.records().get(0).id());
        assertEquals("TCP", result.records().get(0).protocol());
        assertTrue(result.records().get(0).flags().contains("IMPORTED"));
        assertEquals("IMPORTED", result.records().get(0).label());
    }

    @Test
    @DisplayName("A file without a header falls back to the standard column order")
    void fallsBackWithoutHeader() {
        String log = """
                1756900800.000000\tC9\t10.0.0.7\t52000\t198.51.100.7\t8080\ttcp\thttp\t0.500000\t10\t20\tREJ
                """;
        ZeekImportResult result = new ZeekConnLogParser().parse(log, "bare.log");
        assertEquals(1, result.flowsParsed());
        FlowRecord record = result.records().get(0);
        assertEquals(52_000, record.srcPort());
        assertEquals(8_080, record.dstPort());
        assertEquals("HTTP", record.label());
        assertEquals(List.of("REJ"), record.flags());
    }

    @Test
    @DisplayName("The configured maximum stops the import and is described")
    void stopsAtMaximum() {
        ZeekImportResult result = new ZeekConnLogParser(1).parse(LOG, "conn.log");
        assertEquals(1, result.flowsParsed());
        assertEquals(1, result.skipped());
        assertTrue(result.problems().stream().anyMatch(problem -> problem.contains("maximum of 1")));
    }

    @Test
    @DisplayName("Empty input parses to nothing and a missing file is an error")
    void emptyAndMissingInput() throws IOException {
        ZeekImportResult empty = new ZeekConnLogParser().parse("   ", "empty.log");
        assertEquals(0, empty.linesRead());
        assertEquals(0, empty.flowsParsed());

        Path file = temp.resolve("conn.log");
        Files.writeString(file, LOG);
        ZeekImportResult fromFile = new ZeekConnLogParser().parse(file);
        assertEquals(2, fromFile.flowsParsed());

        assertThrows(IOException.class, () -> new ZeekConnLogParser().parse(temp.resolve("absent.log")));
    }
}
