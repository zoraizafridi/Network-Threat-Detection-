package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertTest {

    private final AlertFactory factory = new AlertFactory();

    @Test
    @DisplayName("Positive: Factory creates correct concrete subclass for each Severity with correct risk increments")
    void testAlertFactoryCreation() {
        Instant now = Instant.now();

        Alert low = factory.create(Severity.LOW, AttackType.PORT_SCAN, "10.0.0.1", "10.0.0.2",
                "PortScanDetector", "Port scan detected", now);
        assertInstanceOf(LowAlert.class, low);
        assertEquals(Severity.LOW, low.getSeverity());
        assertEquals(5.0, low.getRiskIncrement());
        assertEquals(AttackType.PORT_SCAN, low.getAttackType());
        assertEquals("10.0.0.1", low.getSourceIp());
        assertEquals("10.0.0.2", low.getTargetIp());
        assertEquals("PortScanDetector", low.getDetectorName());
        assertEquals("Port scan detected", low.getDescription());
        assertEquals(now, low.getTimestamp());
        assertNotNull(low.getId());

        Alert high = factory.create(Severity.HIGH, AttackType.BRUTE_FORCE, "10.0.0.5", "10.0.0.2",
                "RateThresholdDetector", "Failed login threshold exceeded", now);
        assertInstanceOf(HighAlert.class, high);
        assertEquals(Severity.HIGH, high.getSeverity());
        assertEquals(20.0, high.getRiskIncrement());

        Alert critical = factory.create(Severity.CRITICAL, AttackType.DOS_FLOOD, "10.0.0.9", "10.0.0.2",
                "SignatureDetector", "Critical flood detected", now);
        assertInstanceOf(CriticalAlert.class, critical);
        assertEquals(Severity.CRITICAL, critical.getSeverity());
        assertEquals(50.0, critical.getRiskIncrement());
    }

    @Test
    @DisplayName("Negative and Edge: Null severity and attackType throw NullPointerException")
    void testAlertValidation() {
        Instant now = Instant.now();
        assertThrows(NullPointerException.class, () ->
            factory.create(null, AttackType.PORT_SCAN, "1.1.1.1", "2.2.2.2", "det", "desc", now)
        );
        assertThrows(NullPointerException.class, () ->
            factory.create(Severity.LOW, null, "1.1.1.1", "2.2.2.2", "det", "desc", now)
        );

        Alert alert = factory.create(Severity.LOW, AttackType.DATA_TRANSFER, "1.1.1.1", "2.2.2.2", "det", "desc", null);
        assertNotNull(alert.getTimestamp());
    }

    @Test
    @DisplayName("Equals, hashCode, and toString based on alert id")
    void testAlertEqualsAndHashCode() {
        Instant now = Instant.now();
        LowAlert a1 = new LowAlert("alert-1", now, AttackType.PORT_SCAN, "1.1.1.1", "2.2.2.2", "det", "desc");
        LowAlert a2 = new LowAlert("alert-1", now, AttackType.DOS_FLOOD, "3.3.3.3", "4.4.4.4", "other", "desc");
        HighAlert a3 = new HighAlert("alert-2", now, AttackType.PORT_SCAN, "1.1.1.1", "2.2.2.2", "det", "desc");

        assertEquals(a1, a2);
        assertEquals(a1.hashCode(), a2.hashCode());
        assertNotEquals(a1, a3);
        assertNotEquals(a1, null);
        assertNotNull(a1.toString());
        assertTrue(a1.toString().contains("alert-1"));
    }
}
