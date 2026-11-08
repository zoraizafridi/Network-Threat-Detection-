package pk.ooad.ntd.intel;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pk.ooad.ntd.domain.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
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

    private static final String DIGEST =
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    private static final String JSON_FEED = """
            [
              {"type":"ip","value":"198.51.100.7","label":"known-c2","category":"c2","confidence":90},
              {"type":"domain","value":"login.example.com","category":"phishing","confidence":85},
              {"type":"sha256","value":"%s","category":"malware","confidence":60},
              {"type":"ip","value":"192.0.2.200","category":"scanner","confidence":60,"expires":"2000-01-01T00:00:00Z"},
              {"type":"domain","value":"not a domain!","category":"c2","confidence":90}
            ]
            """.formatted(DIGEST);

    @Test
    @DisplayName("A JSON feed carries the type, category, confidence and expiry")
    void parsesJsonFeed() {
        ThreatIntel intel = ThreatIntel.parse(JSON_FEED, "json-feed", Severity.LOW);
        assertEquals(3, intel.size(), "the expired entry and the malformed value are not matched");
        assertEquals(1, intel.addressCount());
        assertEquals(1, intel.domainCount());
        assertEquals(1, intel.digestCount());
        assertEquals(1, intel.expiredEntries());
        assertEquals(1, intel.skippedLines());
        IntelEntry entry = intel.match("198.51.100.7").orElseThrow();
        assertEquals(Severity.CRITICAL, entry.severity(), "c2 at confidence 90 is critical");
        assertEquals("c2", entry.category());
        assertEquals(90, entry.confidence());
        assertEquals("json-feed", entry.source());
    }

    @Test
    @DisplayName("Domains match the name and any subdomain, digests match exactly")
    void matchesDomainAndDigest() {
        ThreatIntel intel = ThreatIntel.parse(JSON_FEED, "f", Severity.HIGH);
        assertEquals("login.example.com", intel.matchDomain("login.example.com").orElseThrow().value());
        assertEquals("login.example.com", intel.matchDomain("Mail.Login.Example.COM").orElseThrow().value());
        assertTrue(intel.matchDomain("example.com").isEmpty(), "a parent name is not listed");
        assertTrue(intel.matchDomain("login.example.com.evil.test").isEmpty());
        assertTrue(intel.matchHash(DIGEST).isPresent());
        assertTrue(intel.matchHash(DIGEST.toUpperCase()).isPresent(), "digests compare case insensitively");
        assertTrue(intel.matchHash(DIGEST.substring(1)).isEmpty());
    }

    @Test
    @DisplayName("A payload is searched for a listed domain and for a listed digest")
    void matchesPayload() {
        ThreatIntel intel = ThreatIntel.parse(JSON_FEED, "f", Severity.HIGH);
        assertEquals("login.example.com",
                intel.matchPayload("GET /signin?host=login.example.com HTTP/1.1").orElseThrow().value());
        assertEquals(DIGEST, intel.matchPayload("upload sha256=" + DIGEST).orElseThrow().value());
        assertTrue(intel.matchPayload("GET /index.html").isEmpty());
        assertTrue(intel.matchPayload(null).isEmpty());
    }

    @Test
    @DisplayName("Severity follows the category and then the confidence")
    void severityFollowsCategoryAndConfidence() {
        assertEquals(Severity.CRITICAL, ThreatIntel.severityFor("c2", 90, Severity.LOW));
        assertEquals(Severity.HIGH, ThreatIntel.severityFor("c2", 60, Severity.LOW));
        assertEquals(Severity.LOW, ThreatIntel.severityFor("c2", 10, Severity.LOW));
        assertEquals(Severity.HIGH, ThreatIntel.severityFor("scanner", 90, Severity.LOW));
        assertEquals(Severity.LOW, ThreatIntel.severityFor("miner", 99, Severity.LOW));
        assertEquals(Severity.HIGH, ThreatIntel.severityFor("unknown", 99, Severity.HIGH));
    }

    @Test
    @DisplayName("An expiry in the past stops the entry from matching")
    void expiredEntriesNeverMatch() {
        String feed = "[{\"type\":\"ip\",\"value\":\"192.0.2.9\",\"category\":\"c2\",\"confidence\":90,"
                + "\"expires\":\"2026-01-01T00:00:00Z\"}]";
        ThreatIntel before = ThreatIntel.parse(feed, "f", Severity.HIGH, Instant.parse("2025-06-01T00:00:00Z"));
        assertEquals(1, before.size());
        assertEquals(0, before.expiredEntries());
        ThreatIntel after = ThreatIntel.parse(feed, "f", Severity.HIGH, Instant.parse("2026-06-01T00:00:00Z"));
        assertEquals(0, after.size());
        assertEquals(1, after.expiredEntries());
        assertTrue(after.match("192.0.2.9").isEmpty());
    }

    @Test
    @DisplayName("A malformed JSON feed leaves nothing to match rather than throwing")
    void malformedJsonYieldsAnEmptyFeed() {
        ThreatIntel intel = ThreatIntel.parse("[{\"value\": }]", "f", Severity.HIGH);
        assertEquals(0, intel.size());
        assertTrue(intel.match("198.51.100.7").isEmpty());
    }
}
