package pk.ooad.ntd.simulation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackGeneratorsTest {

    private final Instant now = Instant.parse("2026-11-05T12:00:00Z");

    @Test
    @DisplayName("PortScanGenerator: Generates multiple distinct ports with EventType.CONNECT")
    void testPortScanGenerator() {
        PortScanGenerator generator = new PortScanGenerator();
        List<NetworkEvent> events = generator.generate("192.168.1.100", "192.168.1.1", now, new Random(42L));

        assertNotNull(events);
        assertTrue(events.size() >= 10, "Should generate scan attempts on multiple ports");

        Set<Integer> portsScanned = new HashSet<>();
        for (NetworkEvent e : events) {
            assertEquals("192.168.1.100", e.sourceIp());
            assertEquals("192.168.1.1", e.destIp());
            assertEquals(EventType.CONNECT, e.type());
            assertFalse(e.success(), "Port scan probes are typically non-successful / syn");
            portsScanned.add(e.port());
        }

        assertTrue(portsScanned.size() >= 10, "Distinct ports must be targeted during port scan");
    }

    @Test
    @DisplayName("BruteForceGenerator: Generates failed logins with EventType.LOGIN_ATTEMPT")
    void testBruteForceGenerator() {
        BruteForceGenerator generator = new BruteForceGenerator();
        List<NetworkEvent> events = generator.generate("10.0.0.50", "10.0.0.2", now, new Random(42L));

        assertNotNull(events);
        assertTrue(events.size() >= 10, "Brute force should generate multiple login attempts");

        for (NetworkEvent e : events) {
            assertEquals("10.0.0.50", e.sourceIp());
            assertEquals("10.0.0.2", e.destIp());
            assertEquals(EventType.LOGIN_ATTEMPT, e.type());
            assertFalse(e.success(), "Brute force attempts must be failed logins");
            assertEquals(22, e.port());
        }
    }

    @Test
    @DisplayName("DosFloodGenerator: Generates high request volume targeting single service")
    void testDosFloodGenerator() {
        DosFloodGenerator generator = new DosFloodGenerator();
        List<NetworkEvent> events = generator.generate("10.0.0.99", "10.0.0.1", now, new Random(42L));

        assertNotNull(events);
        assertTrue(events.size() >= 30, "DoS flood should generate burst of events");

        for (NetworkEvent e : events) {
            assertEquals("10.0.0.99", e.sourceIp());
            assertEquals("10.0.0.1", e.destIp());
            assertEquals(EventType.REQUEST, e.type());
            assertEquals(80, e.port());
        }
    }

    @Test
    @DisplayName("DataTransferGenerator: Generates large volume data transfers with EventType.DATA_TRANSFER")
    void testDataTransferGenerator() {
        DataTransferGenerator generator = new DataTransferGenerator();
        List<NetworkEvent> events = generator.generate("10.0.0.2", "198.51.100.4", now, new Random(42L));

        assertNotNull(events);
        assertTrue(events.size() >= 3, "Should generate exfiltration chunks");

        for (NetworkEvent e : events) {
            assertEquals("10.0.0.2", e.sourceIp());
            assertEquals("198.51.100.4", e.destIp());
            assertEquals(EventType.DATA_TRANSFER, e.type());
            assertTrue(e.bytes() >= 500_000L, "Exfiltration events must involve large byte payloads");
            assertTrue(e.success());
        }
    }

    @Test
    @DisplayName("Negative: Null validation for generator parameters")
    void testGeneratorNullValidation() {
        PortScanGenerator ps = new PortScanGenerator();
        assertThrows(NullPointerException.class, () -> ps.generate("1.1.1.1", "2.2.2.2", null, new Random(1L)));
        assertThrows(NullPointerException.class, () -> ps.generate("1.1.1.1", "2.2.2.2", now, null));

        BruteForceGenerator bf = new BruteForceGenerator();
        assertThrows(NullPointerException.class, () -> bf.generate("1.1.1.1", "2.2.2.2", null, new Random(1L)));
        assertThrows(NullPointerException.class, () -> bf.generate("1.1.1.1", "2.2.2.2", now, null));

        DosFloodGenerator df = new DosFloodGenerator();
        assertThrows(NullPointerException.class, () -> df.generate("1.1.1.1", "2.2.2.2", null, new Random(1L)));
        assertThrows(NullPointerException.class, () -> df.generate("1.1.1.1", "2.2.2.2", now, null));

        DataTransferGenerator dt = new DataTransferGenerator();
        assertThrows(NullPointerException.class, () -> dt.generate("1.1.1.1", "2.2.2.2", null, new Random(1L)));
        assertThrows(NullPointerException.class, () -> dt.generate("1.1.1.1", "2.2.2.2", now, null));
    }
}
