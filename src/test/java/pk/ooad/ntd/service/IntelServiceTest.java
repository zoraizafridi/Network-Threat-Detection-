package pk.ooad.ntd.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.detection.ThreatIntelDetector;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.intel.IntelEntry;
import pk.ooad.ntd.intel.ThreatIntel;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntelServiceTest {

    private static final String FEED = "threat-intel.json";
    private static final String ADDRESS = "198.51.100.7";

    private ThreatIntelDetector detector(ThreatIntel feed) {
        return new ThreatIntelDetector("ThreatIntelDetector", feed, true);
    }

    private ThreatIntel inline() {
        return ThreatIntel.parse("203.0.113.0/24 scanner HIGH\n", "inline", Severity.HIGH);
    }

    @Test
    @DisplayName("Status reports the feed the detector actually matches against")
    void statusDescribesTheDetectorFeed() {
        ThreatIntelDetector detector = detector(inline());
        IntelService service = new IntelService(detector, "inline-feed", true, Severity.HIGH);

        IntelService.Status status = service.status();
        assertTrue(status.wired());
        assertTrue(status.enabled());
        assertEquals("inline-feed", status.feed());
        assertEquals(1, status.entries());
        assertEquals(1, status.addresses());
        assertEquals(0, status.domains());
        assertEquals(0, status.digests());
        assertEquals(0L, status.skipped());
        assertEquals(0L, status.expired());
        assertEquals("inline", status.source());
        assertNull(status.lastReloadAt(), "nothing has been reloaded yet");
        assertEquals(1, detector.feedSize());
        assertEquals("inline-feed", service.feedPath());
        assertTrue(service.isEnabled());
    }

    @Test
    @DisplayName("The packaged feed reloads into the detector and is matchable at once")
    void reloadLoadsThePackagedFeed() throws IOException {
        ThreatIntelDetector detector = detector(ThreatIntel.empty("none"));
        IntelService service = new IntelService(detector, FEED, true, Severity.HIGH);
        assertEquals(0, service.status().entries());

        Instant before = Instant.now();
        IntelService.Status status = service.reload();

        assertEquals(49, status.entries(), "fifty entries, one of them expired");
        assertEquals(19, status.addresses());
        assertEquals(15, status.domains());
        assertEquals(15, status.digests());
        assertEquals(0L, status.skipped());
        assertEquals(1L, status.expired());
        assertEquals(FEED, status.source());
        assertEquals(status.entries(), detector.feedSize());
        assertNotNull(status.lastReloadAt());
        assertFalse(status.lastReloadAt().isBefore(before));

        Optional<IntelEntry> hit = detector.feed().match(ADDRESS);
        assertTrue(hit.isPresent(), "the reloaded feed matches a listed address");
        assertEquals("known-c2", hit.get().label());
        assertEquals(Severity.CRITICAL, hit.get().severity());
        assertTrue(detector.feed().matchDomain("sub.update.example.org").isPresent());
        assertTrue(detector.feed().matchHash(
                "2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE").isPresent());
        assertTrue(detector.feed().match("192.0.2.200").isEmpty(), "an expired entry never matches");
    }

    @Test
    @DisplayName("A reload that cannot read its file leaves the previous feed in place")
    void failedReloadKeepsThePreviousFeed() {
        ThreatIntelDetector detector = detector(inline());
        IntelService service = new IntelService(detector, "no-such-feed-file.json", true, Severity.HIGH);

        assertThrows(IOException.class, service::reload);

        assertEquals(1, detector.feedSize(), "the old feed is still the one being matched");
        assertEquals("inline", service.status().source());
        assertNull(service.status().lastReloadAt(), "a failed reload is not recorded as a reload");
    }

    @Test
    @DisplayName("A service without a detector reports an empty feed and is not wired")
    void statusWithoutDetector() {
        IntelService service = new IntelService(null, FEED, false, Severity.LOW);

        IntelService.Status status = service.status();
        assertFalse(status.wired());
        assertFalse(status.enabled());
        assertEquals(FEED, status.feed());
        assertEquals(0, status.entries());
        assertEquals(FEED, status.source());
        assertNull(status.lastReloadAt());
        assertFalse(service.isEnabled());
    }

    @Test
    @DisplayName("The configured service keeps the packaged feed off by default")
    void configuredServiceUsesThePackagedDefaults() {
        IntelService service = new IntelService(detector(ThreatIntel.empty("none")));

        assertEquals(FEED, service.feedPath());
        assertFalse(service.isEnabled(), "the detector stays off until an operator turns it on");
        assertEquals(0, service.status().entries());
    }
}
