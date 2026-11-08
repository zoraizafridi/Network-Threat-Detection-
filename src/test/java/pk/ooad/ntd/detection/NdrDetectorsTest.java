package pk.ooad.ntd.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.intel.ThreatIntel;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NdrDetectorsTest {

    private final Instant base = Instant.parse("2026-11-08T09:00:00Z");

    private NetworkEvent event(long id, Instant at, String src, String dst, int port, long bytes,
                               EventType type, boolean success, String payload) {
        return new NetworkEvent(id, at, src, dst, port, bytes, type, success, payload, true);
    }

    @Test
    @DisplayName("Beaconing: a steady rhythm alerts once, jitter and the cooldown stay quiet")
    void beaconingDetectsRhythm() {
        BeaconingDetector detector = new BeaconingDetector("BeaconingDetector", true, 3, 0.25, 5, 900, 100, 300);

        Optional<Alert> alert = Optional.empty();
        for (int i = 0; i <= 3; i++) {
            alert = detector.analyze(event(i, base.plusSeconds(10L * i), "10.0.0.5", "198.51.100.9",
                    8443, 200, EventType.CONNECT, true, "SYN"));
        }
        assertTrue(alert.isPresent(), "three steady intervals must alert");
        assertEquals(AttackType.PORT_SCAN, alert.get().getAttackType());
        assertEquals(Severity.HIGH, alert.get().getSeverity());
        assertTrue(alert.get().getDescription().contains("every ~10s"));

        assertTrue(detector.analyze(event(9, base.plusSeconds(40), "10.0.0.5", "198.51.100.9",
                8443, 200, EventType.CONNECT, true, "SYN")).isEmpty(),
                "the per-series cooldown must suppress the next beacon");
        assertEquals(1, detector.trackedSeries());

        BeaconingDetector jittery = new BeaconingDetector("Jittery", true, 3, 0.25, 5, 900, 100, 0);
        long[] offsets = {0, 15, 20, 35};
        for (int i = 0; i < offsets.length; i++) {
            assertTrue(jittery.analyze(event(20 + i, base.plusSeconds(offsets[i]), "10.0.0.7",
                    "198.51.100.9", 8443, 200, EventType.CONNECT, true, "SYN")).isEmpty(),
                    "uneven intervals must not look like a beacon");
        }

        BeaconingDetector off = new BeaconingDetector("Off", false, 3, 0.25, 5, 900, 100, 0);
        for (int i = 0; i <= 5; i++) {
            assertTrue(off.analyze(event(40 + i, base.plusSeconds(10L * i), "10.0.0.8",
                    "198.51.100.9", 8443, 200, EventType.CONNECT, true, "SYN")).isEmpty());
        }
        assertFalse(off.isEnabled());
    }

    @Test
    @DisplayName("Data exfiltration: only traffic leaving the internal prefixes counts")
    void exfiltrationIgnoresInternalDestinations() {
        DataExfilDetector detector = new DataExfilDetector("DataExfilDetector", true, 300,
                1_000, 100, 600, List.of("10.", "192.168."));

        for (int i = 0; i < 3; i++) {
            assertTrue(detector.analyze(event(i, base.plusSeconds(i), "10.0.0.5", "10.0.0.9",
                    443, 5_000, EventType.DATA_TRANSFER, true, "DUMP")).isEmpty(),
                    "internal destinations are not an exit");
        }

        assertTrue(detector.analyze(event(10, base.plusSeconds(10), "10.0.0.5", "198.51.100.9",
                443, 600, EventType.DATA_TRANSFER, true, "DUMP")).isEmpty());
        Optional<Alert> alert = detector.analyze(event(11, base.plusSeconds(11), "10.0.0.5",
                "198.51.100.9", 443, 600, EventType.DATA_TRANSFER, true, "DUMP"));
        assertTrue(alert.isPresent(), "crossing the byte ceiling must alert");
        assertEquals(AttackType.DATA_TRANSFER, alert.get().getAttackType());
        assertTrue(alert.get().getDescription().contains("limit 1000"));

        assertTrue(detector.analyze(event(12, base.plusSeconds(12), "10.0.0.5", "198.51.100.9",
                443, 600, EventType.DATA_TRANSFER, true, "DUMP")).isEmpty(), "cooldown applies");
        assertEquals(1, detector.trackedSources());
        assertTrue(detector.isInternal("192.168.1.5"));
        assertFalse(detector.isInternal("198.51.100.9"));
    }

    @Test
    @DisplayName("Lateral movement: distinct hosts inside the window, management ports named")
    void lateralMovementCountsDistinctHosts() {
        LateralMovementDetector detector = new LateralMovementDetector("LateralMovementDetector",
                true, 120, 3, 100, 300, Set.of(445));

        assertTrue(detector.analyze(event(1, base, "10.0.0.5", "10.0.0.11", 445, 100,
                EventType.CONNECT, false, "SYN")).isEmpty());
        assertTrue(detector.analyze(event(2, base.plusSeconds(1), "10.0.0.5", "10.0.0.12", 445, 100,
                EventType.CONNECT, false, "SYN")).isEmpty());
        Optional<Alert> alert = detector.analyze(event(3, base.plusSeconds(2), "10.0.0.5",
                "10.0.0.13", 445, 100, EventType.CONNECT, false, "SYN"));
        assertTrue(alert.isPresent());
        assertEquals(AttackType.PORT_SCAN, alert.get().getAttackType());
        assertTrue(alert.get().getDescription().contains("reached 3 hosts"));
        assertTrue(alert.get().getDescription().contains("management ports [445]"));

        assertTrue(detector.analyze(event(4, base.plusSeconds(200), "10.0.0.5", "10.0.0.14",
                445, 100, EventType.CONNECT, false, "SYN")).isEmpty(),
                "visits outside the window are pruned");
        assertEquals(1, detector.trackedSources());
    }

    @Test
    @DisplayName("Threat intel: a listed source alerts in the bucket the event implies")
    void threatIntelDetectorUsesEventBucket() {
        ThreatIntel intel = ThreatIntel.parse("203.0.113.0/24 scanner HIGH\n", "feed", Severity.HIGH);
        ThreatIntelDetector detector = new ThreatIntelDetector("ThreatIntelDetector", intel, true);

        assertEquals(1, detector.feedSize());
        assertTrue(detector.analyze(event(1, base, "10.0.0.5", "10.0.0.9", 80, 100,
                EventType.REQUEST, true, "GET")).isEmpty());

        Optional<Alert> alert = detector.analyze(event(2, base, "203.0.113.5", "10.0.0.9", 22, 100,
                EventType.LOGIN_ATTEMPT, false, "FAIL"));
        assertTrue(alert.isPresent());
        assertEquals(AttackType.BRUTE_FORCE, alert.get().getAttackType());
        assertEquals(Severity.HIGH, alert.get().getSeverity());
        assertTrue(alert.get().getDescription().contains("scanner"));

        ThreatIntelDetector off = new ThreatIntelDetector("Off", intel, false);
        assertTrue(off.analyze(event(3, base, "203.0.113.5", "10.0.0.9", 22, 100,
                EventType.LOGIN_ATTEMPT, false, "FAIL")).isEmpty());
    }

    @Test
    @DisplayName("An allowlisted address is exempt from beaconing and exfiltration")
    void allowlistsExemptKnownTraffic() {
        BeaconingDetector exempt = new BeaconingDetector("BeaconingDetector", true, 3, 0.25, 5, 900, 100, 0,
                List.of("10.0.3.0/24"));
        for (int i = 0; i <= 5; i++) {
            assertTrue(exempt.analyze(event(i, base.plusSeconds(10L * i), "10.0.3.9", "198.51.100.9",
                    8443, 200, EventType.CONNECT, true, "SYN")).isEmpty(),
                    "an allowlisted source is exempt");
        }
        assertEquals(0, exempt.trackedSeries(), "an exempt source is not even tracked");

        BeaconingDetector judged = new BeaconingDetector("BeaconingDetector", true, 3, 0.25, 5, 900, 100, 0);
        Optional<Alert> alert = Optional.empty();
        for (int i = 0; i <= 3; i++) {
            alert = judged.analyze(event(100 + i, base.plusSeconds(10L * i), "10.0.3.9", "198.51.100.9",
                    8443, 200, EventType.CONNECT, true, "SYN"));
        }
        assertTrue(alert.isPresent(), "the same traffic alerts when no list is set");

        DataExfilDetector exfil = new DataExfilDetector("DataExfilDetector", true, 300, 1_000, 100, 0,
                List.of("203.0.113.0/24"), List.of("10."));
        assertTrue(exfil.analyze(event(200, base, "10.0.0.5", "203.0.113.9", 443, 5_000,
                EventType.DATA_TRANSFER, true, "DUMP")).isEmpty(), "an allowlisted destination is exempt");
        assertTrue(exfil.analyze(event(201, base, "10.0.0.5", "198.51.100.9", 443, 600,
                EventType.DATA_TRANSFER, true, "DUMP")).isEmpty(), "under the ceiling");
        assertTrue(exfil.analyze(event(202, base, "10.0.0.5", "198.51.100.9", 443, 600,
                EventType.DATA_TRANSFER, true, "DUMP")).isPresent(),
                "a destination that is not on the list still alerts");
    }

    @Test
    @DisplayName("A payload match names the indicator, its type and its category")
    void threatIntelMatchesPayload() {
        String feed = """
                [{"type":"domain","value":"update.example.org","category":"c2","confidence":95},
                 {"type":"sha256","value":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae","category":"malware","confidence":90}]
                """;
        ThreatIntelDetector detector = new ThreatIntelDetector("ThreatIntelDetector",
                ThreatIntel.parse(feed, "json", Severity.LOW), true);

        Optional<Alert> domain = detector.analyze(event(1, base, "10.0.0.5", "10.0.0.9", 443, 100,
                EventType.REQUEST, true, "GET https://update.example.org/loader.bin"));
        assertTrue(domain.isPresent());
        assertEquals(Severity.CRITICAL, domain.get().getSeverity());
        assertTrue(domain.get().getDescription().contains("domain indicator update.example.org"));
        assertTrue(domain.get().getDescription().contains("category c2"));

        Optional<Alert> digest = detector.analyze(event(2, base, "10.0.0.5", "10.0.0.9", 443, 100,
                EventType.DATA_TRANSFER, true,
                "POST sha256=2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"));
        assertTrue(digest.isPresent());
        assertEquals(AttackType.DATA_TRANSFER, digest.get().getAttackType());
        assertTrue(detector.analyze(event(3, base, "10.0.0.5", "10.0.0.9", 443, 100,
                EventType.REQUEST, true, "GET /index.html")).isEmpty());
    }

    @Test
    @DisplayName("Flood detector: threshold crossing from several sources, window expiry, allowlist, disabled by default")
    void floodDetectsDistributedVolume() {
        FloodDetector detector = new FloodDetector("FloodDetector", true, 60, 5, 100, 300, List.of("10.0.0.99"));

        Optional<Alert> alert = Optional.empty();
        for (int i = 0; i < 5; i++) {
            assertTrue(detector.analyze(event(i, base.plusSeconds(i), "10.0.0." + (10 + i), "10.0.0.2",
                    80, 100, EventType.CONNECT, true, "")).isEmpty());
        }
        alert = detector.analyze(event(5, base.plusSeconds(5), "10.0.0.15", "10.0.0.2",
                80, 100, EventType.CONNECT, true, ""));
        assertTrue(alert.isPresent(), "crossing maxConnections must raise an alert");
        assertEquals(AttackType.DOS_FLOOD, alert.get().getAttackType());
        assertEquals(Severity.HIGH, alert.get().getSeverity());
        assertTrue(alert.get().getDescription().contains("10.0.0.2"));
        assertTrue(alert.get().getDescription().contains("6 connections"));
        assertTrue(alert.get().getDescription().contains("6 distinct sources"));

        assertTrue(detector.analyze(event(6, base.plusSeconds(6), "10.0.0.16", "10.0.0.2",
                80, 100, EventType.CONNECT, true, "")).isEmpty(), "cooldown applies");

        FloodDetector windowDetector = new FloodDetector("WindowExpiry", true, 10, 3, 100, 0);
        for (int i = 0; i < 3; i++) {
            assertTrue(windowDetector.analyze(event(20 + i, base.plusSeconds(i), "10.0.0." + i, "10.0.0.3",
                    80, 100, EventType.CONNECT, true, "")).isEmpty());
        }
        assertTrue(windowDetector.analyze(event(23, base.plusSeconds(15), "10.0.0.4", "10.0.0.3",
                80, 100, EventType.CONNECT, true, "")).isEmpty(), "window expiry resets the count");

        FloodDetector allowlistDetector = new FloodDetector("Allowlist", true, 60, 2, 100, 0, List.of("10.0.0.99"));
        for (int i = 0; i < 5; i++) {
            assertTrue(allowlistDetector.analyze(event(30 + i, base.plusSeconds(i), "10.0.0." + i, "10.0.0.99",
                    80, 100, EventType.CONNECT, true, "")).isEmpty(), "allowlisted destination never alerts");
        }

        FloodDetector disabled = new FloodDetector("Disabled", false, 60, 2, 100, 0);
        for (int i = 0; i < 5; i++) {
            assertTrue(disabled.analyze(event(40 + i, base.plusSeconds(i), "10.0.0." + i, "10.0.0.4",
                    80, 100, EventType.CONNECT, true, "")).isEmpty());
        }
        assertFalse(disabled.isEnabled());
    }

    @Test
    @DisplayName("The NDR detector set is additive and silent unless configured")
    void ndrSetIsOffByDefault() {
        List<Detector> ndr = new DetectorFactory().createNdr();
        assertEquals(5, ndr.size());
        NetworkEvent plain = event(1, base, "10.0.0.5", "10.0.0.9", 80, 100,
                EventType.REQUEST, true, "GET");
        for (Detector detector : ndr) {
            assertTrue(detector.analyze(plain).isEmpty(), detector.getName() + " must be quiet by default");
        }
        assertEquals(4, new DetectorFactory().createAll().size(), "the core contract is unchanged");
    }

    @Test
    @DisplayName("The engine admission seam refuses events before observers and detectors")
    void engineAdmissionDropsEvents() throws Exception {
        AlertBus bus = new AlertBus();
        DetectionEngine engine = new DetectionEngine(new LinkedBlockingQueue<>(), bus);
        AtomicInteger published = new AtomicInteger();
        bus.subscribe(alert -> published.incrementAndGet());
        engine.addDetector(new SignatureDetector());
        NetworkEvent blocked = event(1, base, "10.0.0.66", "10.0.0.9", 31337, 100,
                EventType.REQUEST, true, "GET");
        assertTrue(engine.getAdmission().test(blocked), "the default admits everything");

        engine.setAdmission(event -> !"10.0.0.66".equals(event.sourceIp()));
        engine.start();
        try {
            engine.getQueue().offer(blocked);
            long deadline = System.currentTimeMillis() + 5_000;
            while (engine.getDroppedEvents() == 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertEquals(1, engine.getDroppedEvents());
            assertEquals(0, published.get());
        } finally {
            engine.stop();
        }
    }
}
