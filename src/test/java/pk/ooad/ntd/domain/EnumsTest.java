package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EnumsTest {

    @Test
    @DisplayName("AssetType constants and values match specification")
    void testAssetTypeConstants() {
        AssetType[] expected = {
            AssetType.SERVER,
            AssetType.WORKSTATION,
            AssetType.ROUTER,
            AssetType.IOT_DEVICE
        };
        assertArrayEquals(expected, AssetType.values());
        assertEquals(4, AssetType.values().length);
        assertEquals(AssetType.SERVER, AssetType.valueOf("SERVER"));
        assertEquals(AssetType.WORKSTATION, AssetType.valueOf("WORKSTATION"));
        assertEquals(AssetType.ROUTER, AssetType.valueOf("ROUTER"));
        assertEquals(AssetType.IOT_DEVICE, AssetType.valueOf("IOT_DEVICE"));
    }

    @Test
    @DisplayName("AssetStatus constants and values match specification")
    void testAssetStatusConstants() {
        AssetStatus[] expected = {
            AssetStatus.NORMAL,
            AssetStatus.SUSPICIOUS,
            AssetStatus.COMPROMISED
        };
        assertArrayEquals(expected, AssetStatus.values());
        assertEquals(3, AssetStatus.values().length);
        assertEquals(AssetStatus.NORMAL, AssetStatus.valueOf("NORMAL"));
        assertEquals(AssetStatus.SUSPICIOUS, AssetStatus.valueOf("SUSPICIOUS"));
        assertEquals(AssetStatus.COMPROMISED, AssetStatus.valueOf("COMPROMISED"));
    }

    @Test
    @DisplayName("LinkStatus constants and values match specification")
    void testLinkStatusConstants() {
        LinkStatus[] expected = {
            LinkStatus.NORMAL,
            LinkStatus.COMPROMISED
        };
        assertArrayEquals(expected, LinkStatus.values());
        assertEquals(2, LinkStatus.values().length);
        assertEquals(LinkStatus.NORMAL, LinkStatus.valueOf("NORMAL"));
        assertEquals(LinkStatus.COMPROMISED, LinkStatus.valueOf("COMPROMISED"));
    }

    @Test
    @DisplayName("Severity constants and values match specification")
    void testSeverityConstants() {
        Severity[] expected = {
            Severity.LOW,
            Severity.HIGH,
            Severity.CRITICAL
        };
        assertArrayEquals(expected, Severity.values());
        assertEquals(3, Severity.values().length);
        assertEquals(Severity.LOW, Severity.valueOf("LOW"));
        assertEquals(Severity.HIGH, Severity.valueOf("HIGH"));
        assertEquals(Severity.CRITICAL, Severity.valueOf("CRITICAL"));
    }

    @Test
    @DisplayName("AttackType constants and values match specification")
    void testAttackTypeConstants() {
        AttackType[] expected = {
            AttackType.PORT_SCAN,
            AttackType.BRUTE_FORCE,
            AttackType.DOS_FLOOD,
            AttackType.DATA_TRANSFER
        };
        assertArrayEquals(expected, AttackType.values());
        assertEquals(4, AttackType.values().length);
        assertEquals(AttackType.PORT_SCAN, AttackType.valueOf("PORT_SCAN"));
        assertEquals(AttackType.BRUTE_FORCE, AttackType.valueOf("BRUTE_FORCE"));
        assertEquals(AttackType.DOS_FLOOD, AttackType.valueOf("DOS_FLOOD"));
        assertEquals(AttackType.DATA_TRANSFER, AttackType.valueOf("DATA_TRANSFER"));
    }

    @Test
    @DisplayName("EventType constants and values match specification")
    void testEventTypeConstants() {
        EventType[] expected = {
            EventType.CONNECT,
            EventType.LOGIN_ATTEMPT,
            EventType.REQUEST,
            EventType.DATA_TRANSFER
        };
        assertArrayEquals(expected, EventType.values());
        assertEquals(4, EventType.values().length);
        assertEquals(EventType.CONNECT, EventType.valueOf("CONNECT"));
        assertEquals(EventType.LOGIN_ATTEMPT, EventType.valueOf("LOGIN_ATTEMPT"));
        assertEquals(EventType.REQUEST, EventType.valueOf("REQUEST"));
        assertEquals(EventType.DATA_TRANSFER, EventType.valueOf("DATA_TRANSFER"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"INVALID", "unknown", "server", "ROOT", ""})
    @DisplayName("Negative case: Invalid names throw IllegalArgumentException")
    void testInvalidEnumValueOf(String invalidName) {
        assertThrows(IllegalArgumentException.class, () -> AssetType.valueOf(invalidName));
        assertThrows(IllegalArgumentException.class, () -> AssetStatus.valueOf(invalidName));
        assertThrows(IllegalArgumentException.class, () -> LinkStatus.valueOf(invalidName));
        assertThrows(IllegalArgumentException.class, () -> Severity.valueOf(invalidName));
        assertThrows(IllegalArgumentException.class, () -> AttackType.valueOf(invalidName));
        assertThrows(IllegalArgumentException.class, () -> EventType.valueOf(invalidName));
    }

    @Test
    @DisplayName("Edge case: Null argument throws NullPointerException")
    void testNullEnumValueOf() {
        assertThrows(NullPointerException.class, () -> AssetType.valueOf(null));
        assertThrows(NullPointerException.class, () -> AssetStatus.valueOf(null));
        assertThrows(NullPointerException.class, () -> LinkStatus.valueOf(null));
        assertThrows(NullPointerException.class, () -> Severity.valueOf(null));
        assertThrows(NullPointerException.class, () -> AttackType.valueOf(null));
        assertThrows(NullPointerException.class, () -> EventType.valueOf(null));
    }
}

