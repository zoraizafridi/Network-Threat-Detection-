package pk.ooad.ntd.correlation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Severity;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SiemCorrelatorTest {

    private final Instant base = Instant.parse("2026-11-08T07:00:00Z");
    private final AlertFactory factory = new AlertFactory();

    private Alert alert(AttackType type, String source, String target, Instant at) {
        return factory.create(Severity.HIGH, type, source, target, "Detector", "signal", at);
    }

    private SiemCorrelator correlator(AlertBus bus) {
        return new SiemCorrelator(bus, true, 2, 600, 600, 100, Severity.CRITICAL);
    }

    @Test
    @DisplayName("Two distinct attack types from one source escalate once")
    void distinctTypesEscalate() {
        AlertBus bus = new AlertBus();
        List<Alert> correlated = new CopyOnWriteArrayList<>();
        bus.subscribe(alert -> {
            if (SiemCorrelator.DETECTOR_NAME.equals(alert.getDetectorName())) {
                correlated.add(alert);
            }
        });
        SiemCorrelator correlator = correlator(bus);
        bus.subscribe(correlator);

        bus.publish(alert(AttackType.PORT_SCAN, "10.0.0.5", "10.0.0.9", base));
        assertTrue(correlated.isEmpty(), "one signal is not a campaign");

        bus.publish(alert(AttackType.BRUTE_FORCE, "10.0.0.5", "10.0.0.9", base.plusSeconds(1)));
        assertEquals(1, correlated.size());
        Alert escalation = correlated.get(0);
        assertEquals(SiemCorrelator.DETECTOR_NAME, escalation.getDetectorName());
        assertEquals(Severity.CRITICAL, escalation.getSeverity());
        assertEquals("10.0.0.5", escalation.getSourceIp());
        assertTrue(escalation.getDescription().contains("2 distinct attack types"));
        assertTrue(escalation.getDescription().contains("PORT_SCAN"));
        assertTrue(escalation.getDescription().contains("BRUTE_FORCE"));

        bus.publish(alert(AttackType.DOS_FLOOD, "10.0.0.5", "10.0.0.10", base.plusSeconds(2)));
        assertEquals(1, correlated.size(), "the cooldown holds the next escalation back");

        SiemCorrelator.Status status = correlator.status();
        assertTrue(status.enabled());
        assertEquals(1, status.trackedSources());
        assertEquals(3, status.signals());
        assertEquals(1, status.correlated());
        assertEquals(2, status.minSignals());
    }

    @Test
    @DisplayName("Repeats, other sources, and its own output never correlate")
    void repeatsAndForeignSourcesStayQuiet() {
        AlertBus bus = new AlertBus();
        List<Alert> correlated = new CopyOnWriteArrayList<>();
        bus.subscribe(alert -> {
            if (SiemCorrelator.DETECTOR_NAME.equals(alert.getDetectorName())) {
                correlated.add(alert);
            }
        });
        SiemCorrelator correlator = correlator(bus);
        bus.subscribe(correlator);

        bus.publish(alert(AttackType.PORT_SCAN, "10.0.0.5", "10.0.0.9", base));
        bus.publish(alert(AttackType.PORT_SCAN, "10.0.0.5", "10.0.0.10", base.plusSeconds(1)));
        assertTrue(correlated.isEmpty(), "the same type twice is one fact");

        bus.publish(alert(AttackType.BRUTE_FORCE, "10.0.0.6", "10.0.0.9", base.plusSeconds(2)));
        assertTrue(correlated.isEmpty(), "a different source is a different window");

        bus.publish(alert(AttackType.BRUTE_FORCE, "10.0.0.5", "10.0.0.9", base.plusSeconds(3)));
        assertEquals(1, correlated.size());

        bus.publish(alert(AttackType.DOS_FLOOD, "10.0.0.5", "10.0.0.9", base.plusSeconds(4)));
        assertEquals(1, correlated.size(), "its own escalation is not a new signal");
        assertEquals(1, correlator.status().correlated());
    }

    @Test
    @DisplayName("Signals older than the window are pruned before the decision")
    void windowExpiryPreventsCorrelation() {
        AlertBus bus = new AlertBus();
        List<Alert> correlated = new CopyOnWriteArrayList<>();
        bus.subscribe(alert -> {
            if (SiemCorrelator.DETECTOR_NAME.equals(alert.getDetectorName())) {
                correlated.add(alert);
            }
        });
        SiemCorrelator correlator = correlator(bus);
        bus.subscribe(correlator);

        bus.publish(alert(AttackType.PORT_SCAN, "10.0.0.5", "10.0.0.9", base));
        bus.publish(alert(AttackType.BRUTE_FORCE, "10.0.0.5", "10.0.0.9", base.plusSeconds(601)));
        assertTrue(correlated.isEmpty(), "the scan fell out of the 600s window");
        assertEquals(2, correlator.status().signals(), "both signals were seen, only one stayed in the window");
    }

    @Test
    @DisplayName("A disabled correlator does nothing, and reset clears the counters")
    void disabledAndReset() {
        AlertBus bus = new AlertBus();
        List<Alert> correlated = new CopyOnWriteArrayList<>();
        bus.subscribe(alert -> {
            if (SiemCorrelator.DETECTOR_NAME.equals(alert.getDetectorName())) {
                correlated.add(alert);
            }
        });
        SiemCorrelator off = new SiemCorrelator(bus, false, 2, 600, 600, 100, Severity.HIGH);
        bus.subscribe(off);
        bus.publish(alert(AttackType.PORT_SCAN, "10.0.0.5", "10.0.0.9", base));
        bus.publish(alert(AttackType.BRUTE_FORCE, "10.0.0.5", "10.0.0.9", base.plusSeconds(1)));
        assertFalse(off.isEnabled());
        assertTrue(correlated.isEmpty());
        assertEquals(0, off.status().trackedSources());

        SiemCorrelator on = correlator(bus);
        bus.subscribe(on);
        bus.publish(alert(AttackType.PORT_SCAN, "10.0.0.7", "10.0.0.9", base.plusSeconds(10)));
        bus.publish(alert(AttackType.BRUTE_FORCE, "10.0.0.7", "10.0.0.9", base.plusSeconds(11)));
        assertTrue(on.status().correlated() >= 1);
        on.reset();
        assertEquals(0, on.status().signals());
        assertEquals(0, on.status().correlated());
        assertEquals(0, on.status().trackedSources());
    }
}
