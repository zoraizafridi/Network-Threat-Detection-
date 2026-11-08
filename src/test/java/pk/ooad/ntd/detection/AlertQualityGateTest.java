package pk.ooad.ntd.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The gate that can silence alerts, so every way it says no is pinned down:
 * the repeats it folds, the floor it applies, the bound on its bookkeeping, and
 * the fact that a suppressed alert costs nothing.
 */
class AlertQualityGateTest {

    private static final Instant BASE = Instant.parse("2026-11-08T09:00:00Z");
    private static final AlertFactory FACTORY = new AlertFactory();

    private static Alert alert(AttackType type, String detector, Instant at) {
        return FACTORY.create(Severity.HIGH, type, "10.0.0.5", "10.0.0.9", detector, "synthetic", at);
    }

    @Test
    @DisplayName("A disabled gate allows everything and keeps no key table")
    void disabledGateAllowsEverything() {
        AlertQualityGate gate = new AlertQualityGate(false, 60, Severity.LOW, 100);
        assertFalse(gate.isDedupeEnabled());
        assertEquals(60, gate.getWindowSeconds());
        assertEquals(Severity.LOW, gate.getMinimumSeverity());

        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE)));
        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE)));
        AlertQualityGate.Stats stats = gate.stats();
        assertEquals(0, stats.duplicates());
        assertEquals(0, stats.belowFloor());
        assertEquals(0, stats.tracked(), "dedupe off means nothing is remembered");
        assertEquals("LOW", stats.minimumSeverity());
    }

    @Test
    @DisplayName("A repeat of the same key inside the window collapses into the first")
    void repeatsInsideTheWindowCollapse() {
        AlertQualityGate gate = new AlertQualityGate(true, 60, Severity.LOW, 100);
        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE)));
        assertFalse(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE.plusSeconds(30))));
        assertEquals(1, gate.stats().duplicates());
        assertEquals(1, gate.stats().tracked());

        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE.plusSeconds(61))),
                "past the window the same key is published again");
        assertEquals(1, gate.stats().duplicates());
    }

    @Test
    @DisplayName("A different detector, type, source or target is a different alert")
    void differentKeyIsNotADuplicate() {
        AlertQualityGate gate = new AlertQualityGate(true, 60, Severity.LOW, 100);
        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE)));
        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "PortScanDetector", BASE)));
        assertTrue(gate.allow(alert(AttackType.BRUTE_FORCE, "SignatureDetector", BASE)));
        assertTrue(gate.allow(FACTORY.create(Severity.HIGH, AttackType.PORT_SCAN, "10.0.0.6", "10.0.0.9",
                "SignatureDetector", "other source", BASE)));
        assertTrue(gate.allow(FACTORY.create(Severity.HIGH, AttackType.PORT_SCAN, "10.0.0.5", "10.0.0.7",
                "SignatureDetector", "other target", BASE)));
        assertEquals(0, gate.stats().duplicates());
        assertTrue(gate.stats().tracked() >= 5);
    }

    @Test
    @DisplayName("An alert that arrives older than the last one is out of order, not a duplicate")
    void olderArrivalIsAllowed() {
        AlertQualityGate gate = new AlertQualityGate(true, 60, Severity.LOW, 100);
        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE.plusSeconds(50))));
        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE)),
                "a negative age is not inside a forward window");
        assertEquals(0, gate.stats().duplicates());
    }

    @Test
    @DisplayName("The severity floor drops the tail and counts it")
    void severityFloorDropsTheTail() {
        AlertQualityGate gate = new AlertQualityGate(false, 60, Severity.HIGH, 100);
        assertEquals(Severity.HIGH, gate.getMinimumSeverity());

        assertFalse(gate.allow(FACTORY.create(Severity.LOW, AttackType.PORT_SCAN, "10.0.0.5", "10.0.0.9",
                "SignatureDetector", "low", BASE)));
        assertEquals(1, gate.stats().belowFloor());
        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE)));
        assertEquals(1, gate.stats().belowFloor(), "an allowed alert does not add to the floor count");
    }

    @Test
    @DisplayName("A null alert is refused rather than published")
    void nullAlertIsRefused() {
        AlertQualityGate gate = new AlertQualityGate(true, 60, Severity.LOW, 100);
        assertFalse(gate.allow(null));
        assertEquals(0, gate.stats().duplicates());
        assertEquals(0, gate.stats().belowFloor());
    }

    @Test
    @DisplayName("The key table stays inside its cap however many keys arrive")
    void tableIsBounded() {
        AlertQualityGate gate = new AlertQualityGate(true, 3600, Severity.LOW, 16);
        for (int i = 0; i < 40; i++) {
            Alert candidate = FACTORY.create(Severity.HIGH, AttackType.PORT_SCAN,
                    "10.1.0." + i, "10.0.0.9", "SignatureDetector", "scan " + i, BASE.plusSeconds(i));
            assertTrue(gate.allow(candidate), "seed " + i + " is a new key");
        }
        assertEquals(16, gate.stats().tracked(), "the cap is 16 even after 40 distinct keys");
    }

    @Test
    @DisplayName("reset clears the table and both counters")
    void resetClearsEverything() {
        AlertQualityGate gate = new AlertQualityGate(true, 60, Severity.LOW, 100);
        gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE));
        gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE));
        gate.allow(FACTORY.create(Severity.LOW, AttackType.PORT_SCAN, "10.0.0.5", "10.0.0.9",
                "Floored", "low", BASE));

        gate.reset();
        AlertQualityGate.Stats stats = gate.stats();
        assertEquals(0, stats.duplicates());
        assertEquals(0, stats.belowFloor());
        assertEquals(0, stats.tracked());
        assertTrue(gate.allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE)),
                "after a reset the same key is new again");
    }

    @Test
    @DisplayName("A refused alert does not spend the engine's per-source cooldown")
    void refusedAlertDoesNotSpendTheCooldown() throws Exception {
        AlertBus bus = new AlertBus();
        List<Alert> published = new CopyOnWriteArrayList<>();
        bus.subscribe(published::add);

        DetectionEngine engine = new DetectionEngine(new LinkedBlockingQueue<>(), bus, 300);
        engine.addDetector(new AlwaysAlerts());

        AtomicBoolean first = new AtomicBoolean(true);
        engine.setAlertGate(alert -> {
            if (first.compareAndSet(true, false)) {
                return false;
            }
            return true;
        });
        engine.start();
        try {
            engine.getQueue().add(event(1, BASE));
            engine.getQueue().add(event(2, BASE.plusSeconds(1)));

            long deadline = System.currentTimeMillis() + 5_000;
            while (published.isEmpty() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertEquals(1, published.size(),
                    "the second alert survives both the gate and the 300s source cooldown");
            assertEquals(BASE.plusSeconds(1), published.get(0).getTimestamp());
            assertEquals(BASE.plusSeconds(1), engine.getLastAlertAt().get("10.0.0.5"),
                    "only the published alert marks the cooldown");
        } finally {
            engine.stop();
        }
    }

    @Test
    @DisplayName("A null gate restores the pass-through default")
    void nullGateRestoresTheDefault() {
        DetectionEngine engine = new DetectionEngine(new LinkedBlockingQueue<>(), new AlertBus(), 5);
        engine.setAlertGate(new AlertQualityGate(false, 60, Severity.LOW, 10));
        assertNotSame(AlertGate.ALLOW_ALL, engine.getAlertGate());
        engine.setAlertGate(null);
        assertSame(AlertGate.ALLOW_ALL, engine.getAlertGate());
        assertTrue(engine.getAlertGate().allow(alert(AttackType.PORT_SCAN, "SignatureDetector", BASE)));
    }

    private static NetworkEvent event(long id, Instant at) {
        return new NetworkEvent(id, at, "10.0.0.5", "10.0.0.9", 443, 500, EventType.REQUEST, true, "GET");
    }

    /** A detector with nothing to decide: it raises one alert per event, every time. */
    private static final class AlwaysAlerts extends Detector {

        private AlwaysAlerts() {
            super("AlwaysAlerts");
        }

        @Override
        public Optional<Alert> analyze(NetworkEvent e) {
            return Optional.of(alertFactory.create(Severity.HIGH, AttackType.PORT_SCAN,
                    e.sourceIp(), e.destIp(), name, "synthetic", e.timestamp()));
        }

        @Override
        public void reset() {
        }
    }
}
