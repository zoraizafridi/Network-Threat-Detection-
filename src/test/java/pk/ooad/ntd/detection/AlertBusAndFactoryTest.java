package pk.ooad.ntd.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.LowAlert;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertBusAndFactoryTest {

    @Test
    @DisplayName("AlertBus: Observers receive published alerts; failing listener does not break others")
    void testAlertBusPublishAndIsolation() {
        AlertBus bus = new AlertBus();
        List<Alert> received = new ArrayList<>();
        AtomicBoolean failingListenerRan = new AtomicBoolean(false);

        AlertListener goodListener1 = received::add;
        AlertListener badListener = a -> {
            failingListenerRan.set(true);
            throw new RuntimeException("Listener exploded!");
        };
        AlertListener goodListener2 = received::add;

        bus.subscribe(goodListener1);
        bus.subscribe(badListener);
        bus.subscribe(goodListener2);

        Alert alert = new LowAlert("a-1", Instant.now(), AttackType.PORT_SCAN, "1.1.1.1", "2.2.2.2", "det", "desc");
        bus.publish(alert);

        assertTrue(failingListenerRan.get(), "Failing listener must have executed");
        assertEquals(2, received.size(), "Both good listeners must have received the alert despite exception in bad listener");

        bus.unsubscribe(goodListener1);
        bus.publish(alert);
        assertEquals(3, received.size(), "Only goodListener2 should receive after goodListener1 unsubscribed");

        bus.publish(null);
    }

    @Test
    @DisplayName("DetectorFactory: Creates all specified detectors and validates names")
    void testDetectorFactory() {
        DetectorFactory factory = new DetectorFactory();

        assertInstanceOf(SignatureDetector.class, factory.create("SignatureDetector"));
        assertInstanceOf(RateThresholdDetector.class, factory.create("RateThresholdDetector"));
        assertInstanceOf(PortScanDetector.class, factory.create("PortScanDetector"));
        assertInstanceOf(AnomalyDetector.class, factory.create("AnomalyDetector"));

        List<Detector> all = factory.createAll();
        assertEquals(4, all.size());

        assertThrows(IllegalArgumentException.class, () -> factory.create("NonExistentDetector"));
        assertThrows(NullPointerException.class, () -> factory.create(null));
    }
}

