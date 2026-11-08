package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NetworkAssetTest {

    @Test
    @DisplayName("Positive: Subclasses instantiate with proper defaults and attributes")
    void testSubclassDefaultsAndAttributes() {
        Server server = new Server("srv-1", "Web Server", "10.0.0.1", 4, List.of("HTTP", "HTTPS"));
        assertEquals("srv-1", server.getId());
        assertEquals("Web Server", server.getName());
        assertEquals("10.0.0.1", server.getIp());
        assertEquals(AssetType.SERVER, server.getType());
        assertEquals(4, server.getCriticality());
        assertEquals(0.0, server.getRiskScore());
        assertEquals(AssetStatus.NORMAL, server.getStatus());
        assertEquals(1.5, server.getDefaultRiskWeight());
        assertTrue(server.getTypicalPorts().containsAll(List.of(80, 443)));
        assertTrue(server.getServices().contains("HTTP"));

        Workstation ws = new Workstation("ws-1", "Alice PC", "10.0.0.2", 2, "Alice");
        assertEquals(AssetType.WORKSTATION, ws.getType());
        assertEquals("Alice", ws.getOwner());
        assertEquals(1.0, ws.getDefaultRiskWeight());
        assertTrue(ws.getTypicalPorts().contains(445));

        Router router = new Router("rt-1", "Edge Router", "10.0.0.254", 5, 8);
        assertEquals(AssetType.ROUTER, router.getType());
        assertEquals(8, router.getInterfaceCount());
        assertEquals(1.2, router.getDefaultRiskWeight());
        assertTrue(router.getTypicalPorts().contains(22));

        IoTDevice iot = new IoTDevice("iot-1", "Cam 1", "10.0.0.50", 1, "2.1.0", true);
        assertEquals(AssetType.IOT_DEVICE, iot.getType());
        assertEquals("2.1.0", iot.getFirmwareVersion());
        assertTrue(iot.hasDefaultCredentials());
        assertTrue(iot.isDefaultCredentials());
        assertEquals(0.8, iot.getDefaultRiskWeight());
        assertTrue(iot.getTypicalPorts().contains(554));
    }

    @Test
    @DisplayName("Risk score bounding: stays between 0 and 100, addRisk never pushes past limits")
    void testRiskScoreBounding() {
        Server server = new Server("srv-risk", "Risk Test", "10.0.0.99", 3);
        assertEquals(0.0, server.getRiskScore(), "Initial riskScore must be 0");

        // Negative delta while at 0 should stay clamped at 0
        server.addRisk(-15.0);
        assertEquals(0.0, server.getRiskScore(), "Risk score must not go below 0");

        server.addRisk(40.0);
        assertEquals(40.0, server.getRiskScore());

        // Addition that would exceed 100 must clamp at 100
        server.addRisk(75.0);
        assertEquals(100.0, server.getRiskScore(), "Risk score must be clamped at 100");

        // Further addition must not push past 100
        server.addRisk(50.0);
        assertEquals(100.0, server.getRiskScore(), "Risk score must remain at 100");

        server.addRisk(-30.0);
        assertEquals(70.0, server.getRiskScore());

        // Extreme reduction past 0 clamps at 0
        server.addRisk(-120.0);
        assertEquals(0.0, server.getRiskScore(), "Risk score must clamp at 0 on large negative delta");

        server.addRisk(85.0);
        assertEquals(85.0, server.getRiskScore());
        server.resetRisk();
        assertEquals(0.0, server.getRiskScore(), "resetRisk must reset risk score to 0");
    }

    @Test
    @DisplayName("Status transitions and null checks")
    void testStatusAndNullValidation() {
        Server server = new Server("srv-status", "Status Test", "10.0.0.88", 2);
        assertEquals(AssetStatus.NORMAL, server.getStatus());

        server.setStatus(AssetStatus.SUSPICIOUS);
        assertEquals(AssetStatus.SUSPICIOUS, server.getStatus());

        server.setStatus(AssetStatus.COMPROMISED);
        assertEquals(AssetStatus.COMPROMISED, server.getStatus());

        assertThrows(NullPointerException.class, () -> server.setStatus(null));
    }

    @Test
    @DisplayName("Equals, hashCode, and toString based on asset id")
    void testEqualsAndHashCode() {
        Server s1 = new Server("srv-eq", "Server A", "10.0.0.1", 3);
        Server s2 = new Server("srv-eq", "Server B", "10.0.0.2", 5);
        Workstation w1 = new Workstation("srv-eq", "WS", "10.0.0.3", 1);
        Server s3 = new Server("srv-diff", "Server A", "10.0.0.1", 3);

        assertEquals(s1, s2);
        assertEquals(s1.hashCode(), s2.hashCode());
        assertNotEquals(s1, s3);
        assertNotEquals(s1, w1);
        assertNotEquals(s1, null);

        assertNotNull(s1.toString());
        assertTrue(s1.toString().contains("srv-eq"));
    }
}

