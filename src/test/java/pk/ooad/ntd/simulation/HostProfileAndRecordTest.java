package pk.ooad.ntd.simulation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.AttackType;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HostProfileAndRecordTest {

    @Test
    @DisplayName("HostProfile: Defaults, custom initialization, and setters")
    void testHostProfile() {
        HostProfile defaultProfile = new HostProfile();
        assertEquals(512.0, defaultProfile.getMeanBytes());
        assertEquals(64.0, defaultProfile.getStdBytes());
        assertEquals(5.0, defaultProfile.getEventsPerSecond());
        assertTrue(defaultProfile.getCommonPorts().contains(80));

        HostProfile custom = new HostProfile(1024.0, 128.0, List.of(8080, 8443), 10.0);
        assertEquals(1024.0, custom.getMeanBytes());
        assertEquals(128.0, custom.getStdBytes());
        assertEquals(10.0, custom.getEventsPerSecond());
        assertEquals(List.of(8080, 8443), custom.getCommonPorts());

        custom.setMeanBytes(2048.0);
        custom.setStdBytes(256.0);
        custom.setEventsPerSecond(20.0);
        custom.setCommonPorts(List.of(22));

        assertEquals(2048.0, custom.getMeanBytes());
        assertEquals(256.0, custom.getStdBytes());
        assertEquals(20.0, custom.getEventsPerSecond());
        assertEquals(List.of(22), custom.getCommonPorts());
    }

    @Test
    @DisplayName("AttackRecord: Getters, equality, and validation")
    void testAttackRecord() {
        Instant now = Instant.parse("2026-11-05T15:00:00Z");
        AttackRecord r1 = new AttackRecord(AttackType.PORT_SCAN, "10.0.0.1", "10.0.0.2", now);
        AttackRecord r2 = new AttackRecord(AttackType.PORT_SCAN, "10.0.0.1", "10.0.0.2", now);
        AttackRecord r3 = new AttackRecord(AttackType.BRUTE_FORCE, "10.0.0.1", "10.0.0.2", now);

        assertEquals(AttackType.PORT_SCAN, r1.getType());
        assertEquals("10.0.0.1", r1.getSource());
        assertEquals("10.0.0.2", r1.getTarget());
        assertEquals(now, r1.getStartTime());

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
        assertNotEquals(r1, r3);
        assertNotEquals(r1, null);
        assertNotNull(r1.toString());

        assertThrows(NullPointerException.class, () ->
            new AttackRecord(null, "10.0.0.1", "10.0.0.2", now)
        );
        assertThrows(NullPointerException.class, () ->
            new AttackRecord(AttackType.PORT_SCAN, "10.0.0.1", "10.0.0.2", null)
        );
    }
}
