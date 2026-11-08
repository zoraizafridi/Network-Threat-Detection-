package pk.ooad.ntd.simulation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScenarioServiceTest {

    private final ScenarioService service = new ScenarioService();

    @Test
    @DisplayName("Every preset is listed under its own name, title and summary")
    void presetsAreListed() {
        List<String> names = new ArrayList<>();
        for (ScenarioService.Preset preset : service.presets()) {
            names.add(preset.name());
            assertFalse(preset.title().isBlank(), "a preset needs a title");
            assertFalse(preset.summary().isBlank(), "a preset needs a summary");
        }
        assertEquals(List.of("port-scan", "brute-force", "flood", "data-transfer", "beaconing",
                "lateral-movement", "intel-contact"), names);
    }

    @Test
    @DisplayName("Beaconing: twelve callbacks thirty seconds apart, bucketed as connections")
    void beaconingIsSteady() {
        List<NetworkEvent> seen = new ArrayList<>();
        ScenarioService.Result result = service.run("beaconing", "10.0.2.12", "198.51.100.9", 7L, seen::add);

        assertEquals("beaconing", result.preset());
        assertEquals("Beaconing", result.title());
        assertEquals(12, result.events());
        assertEquals(12, seen.size());
        assertEquals(List.of(AttackType.PORT_SCAN), result.attackTypes());
        for (int i = 0; i < seen.size(); i++) {
            NetworkEvent event = seen.get(i);
            assertEquals("10.0.2.12", event.sourceIp());
            assertEquals(443, event.port());
            assertEquals(EventType.CONNECT, event.type());
            assertTrue(event.success());
            if (i > 0) {
                long gap = event.timestamp().toEpochMilli() - seen.get(i - 1).timestamp().toEpochMilli();
                assertTrue(gap > 29_500L && gap < 30_500L, "beacons must stay near thirty seconds, was " + gap);
            }
        }
    }

    @Test
    @DisplayName("Lateral movement: six refused logins against six hosts on management ports")
    void lateralMovementSpreadsOverHosts() {
        List<NetworkEvent> seen = new ArrayList<>();
        ScenarioService.Result result = service.run("lateral-movement", "10.0.2.12", "10.0.1.20", 3L, seen::add);

        assertEquals(6, result.events());
        assertEquals(List.of(AttackType.BRUTE_FORCE), result.attackTypes());
        Set<String> hosts = new HashSet<>();
        Set<Integer> ports = new HashSet<>();
        for (NetworkEvent event : seen) {
            assertEquals("10.0.2.12", event.sourceIp());
            assertEquals(EventType.LOGIN_ATTEMPT, event.type());
            assertFalse(event.success(), "lateral attempts are refused");
            assertTrue(event.payload().contains("AUTH_FAILED"));
            hosts.add(event.destIp());
            ports.add(event.port());
        }
        assertEquals(6, hosts.size(), "each attempt reaches a different host");
        assertEquals(Set.of(22, 445, 3389), ports);
    }

    @Test
    @DisplayName("Indicator contact: a listed address fetches a listed domain and digest")
    void indicatorContactCoversAllThreeTypes() {
        List<NetworkEvent> seen = new ArrayList<>();
        ScenarioService.Result result = service.run("intel-contact", "10.0.2.12", "10.0.1.20", 11L, seen::add);

        assertEquals(3, result.events());
        assertEquals("198.51.100.7", seen.get(0).sourceIp(), "the first request comes from a listed address");
        assertTrue(seen.get(1).payload().contains("update.example.org"), "the second names a listed domain");
        assertTrue(seen.get(2).payload().contains(
                "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"),
                "the third carries a listed digest");
        assertTrue(result.attackTypes().contains(AttackType.PORT_SCAN));
        assertTrue(result.attackTypes().contains(AttackType.DATA_TRANSFER));
    }

    @Test
    @DisplayName("The four classic presets offer exactly what their generators build")
    void classicPresetsReuseGenerators() {
        Instant now = Instant.parse("2026-11-08T09:00:00Z");
        String src = "10.0.2.12";
        String dst = "10.0.1.20";

        assertEquals(new PortScanGenerator().generate(src, dst, now, new Random(1L)).size(),
                service.run("port-scan", src, dst, 1L, null).events());
        assertEquals(new BruteForceGenerator().generate(src, dst, now, new Random(1L)).size(),
                service.run("brute-force", src, dst, 1L, null).events());
        assertEquals(new DosFloodGenerator().generate(src, dst, now, new Random(1L)).size(),
                service.run("flood", src, dst, 1L, null).events());
        assertEquals(new DataTransferGenerator().generate(src, dst, now, new Random(1L)).size(),
                service.run("data-transfer", src, dst, 1L, null).events());
    }

    @Test
    @DisplayName("A preset is repeatable under one seed and fills absent endpoints")
    void presetsAreRepeatable() {
        List<NetworkEvent> first = new ArrayList<>();
        List<NetworkEvent> second = new ArrayList<>();
        ScenarioService.Result result = service.run("PORT-SCAN", "  ", null, 42L, first::add);
        service.run("port-scan", "", "", 42L, second::add);

        assertEquals("port-scan", result.preset(), "the name is folded before the lookup");
        assertEquals("10.0.2.12", result.source());
        assertEquals("10.0.1.20", result.target());
        assertEquals(first.size(), second.size());
        for (int i = 0; i < first.size(); i++) {
            assertEquals(first.get(i).port(), second.get(i).port());
            assertEquals(first.get(i).bytes(), second.get(i).bytes());
            assertEquals(first.get(i).sourceIp(), second.get(i).sourceIp());
        }
    }

    @Test
    @DisplayName("An unknown preset is refused rather than guessed")
    void unknownPresetIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> service.run("ddos-everything", null, null, 1L, null));
        assertThrows(IllegalArgumentException.class, () -> service.run(null, null, null, 1L, null));
    }
}
