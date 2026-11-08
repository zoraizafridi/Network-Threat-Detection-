package pk.ooad.ntd.intel;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pk.ooad.ntd.domain.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThreatIntelTest {

    private static final String FEED = """
            # scanner ranges
            203.0.113.0/24   scanner-net   HIGH

            198.51.100.7     known-c2      CRITICAL
            192.0.2.0/24     unlabelled
            not-an-address   broken        LOW
            2001:db8::/32    v6-only       HIGH
            """;

    @TempDir
    Path temp;

    @Test
    @DisplayName("Parsing keeps valid IPv4 entries and counts the rest")
    void parsesAndCountsSkips() {
        ThreatIntel intel = ThreatIntel.parse(FEED, "test-feed", Severity.HIGH);
        assertEquals(3, intel.size(), "two CIDR blocks and one address");
        assertEquals(2, intel.skippedLines(), "the malformed line and the IPv6 block are skipped");
        assertEquals("scanner-net", intel.entries().get(0).label());
        assertEquals(Severity.HIGH, intel.entries().get(0).severity());
        assertEquals("test-feed", intel.entries().get(0).source());
    }

    @Test
    @DisplayName("Matching is prefix-aware and refuses anything that is not IPv4")
    void matchesWithinPrefix() {
        ThreatIntel intel = ThreatIntel.parse(FEED, "test-feed", Severity.HIGH);

        Optional<IntelEntry> inside = intel.match("203.0.113.77");
        assertTrue(inside.isPresent());
        assertEquals("scanner-net", inside.get().label());

        Optional<IntelEntry> exact = intel.match("198.51.100.7");
        assertTrue(exact.isPresent());
        assertEquals("CRITICAL", exact.get().severity().name());

        assertTrue(intel.match("203.0.114.1").isEmpty());
        assertTrue(intel.match("2001:db8::1").isEmpty());
        assertTrue(intel.match("not-an-ip").isEmpty());
        assertTrue(intel.match(null).isEmpty());
    }

    @Test
    @DisplayName("A missing severity falls back to the feed default")
    void fallbackSeverity() {
        ThreatIntel intel = ThreatIntel.parse("192.0.2.0/24 unlabelled", "f", Severity.CRITICAL);
        assertEquals(Severity.CRITICAL, intel.match("192.0.2.9").orElseThrow().severity());

        ThreatIntel defaults = ThreatIntel.parse("192.0.2.0/24 unlabelled", "f", Severity.LOW);
        assertEquals(Severity.LOW, defaults.match("192.0.2.9").orElseThrow().severity());
    }

    @Test
    @DisplayName("A single address matches only itself")
    void singleAddressIsSlashThirtyTwo() {
        ThreatIntel intel = ThreatIntel.parse("198.51.100.7 c2 CRITICAL", "f", Severity.HIGH);
        assertTrue(intel.match("198.51.100.7").isPresent());
        assertFalse(intel.match("198.51.100.8").isPresent());
    }

    @Test
    @DisplayName("Loading reads a file and reports a missing feed")
    void loadsFromFile() throws IOException {
        Path feed = temp.resolve("threat-intel.txt");
        Files.writeString(feed, "203.0.113.9 bad HIGH\n");
        ThreatIntel intel = ThreatIntel.load(feed.toString(), Severity.HIGH);
        assertEquals(1, intel.size());
        assertTrue(intel.match("203.0.113.9").isPresent());

        assertThrows(IOException.class, () -> ThreatIntel.load(temp.resolve("absent.txt").toString(), Severity.HIGH));
    }

    @Test
    @DisplayName("Empty text yields an empty feed rather than an error")
    void emptyFeed() {
        ThreatIntel intel = ThreatIntel.parse(null, null, null);
        assertEquals(0, intel.size());
        assertEquals(0, intel.skippedLines());
        assertTrue(intel.match("10.0.0.1").isEmpty());
    }
}
