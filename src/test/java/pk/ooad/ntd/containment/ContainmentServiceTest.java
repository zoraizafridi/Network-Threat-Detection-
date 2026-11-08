package pk.ooad.ntd.containment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContainmentServiceTest {

    private final Instant base = Instant.parse("2026-11-08T06:00:00Z");

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        private void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private static NetworkEvent from(String source) {
        return new NetworkEvent(1, Instant.parse("2026-11-08T06:00:00Z"), source, "10.0.0.9",
                443, 100, EventType.REQUEST, true, "GET", true);
    }

    private ContainmentService service(MutableClock clock, boolean enabled, boolean auto, boolean enforce,
                                       int maxDurationMinutes) {
        return new ContainmentService(clock, enabled, auto, enforce, 30, maxDurationMinutes, 500, Severity.HIGH);
    }

    @Test
    @DisplayName("Disabled containment admits everything and refuses orders")
    void disabledService() {
        MutableClock clock = new MutableClock(base);
        ContainmentService service = service(clock, false, false, false, 1_440);
        assertTrue(service.admit(from("10.0.0.5")));
        assertThrows(IllegalStateException.class, () -> service.contain("10.0.0.5", 10, "test", "admin"));
        assertFalse(service.status().enabled());
        assertTrue(service.active().isEmpty());
        assertFalse(service.isBlocked("10.0.0.5"));
    }

    @Test
    @DisplayName("A manual order blocks and drops until it is released")
    void manualContainmentEnforces() {
        MutableClock clock = new MutableClock(base);
        ContainmentService service = service(clock, true, false, true, 1_440);

        ContainmentService.Action action = service.contain("10.0.0.5", 30, "human review", "admin");
        assertEquals("10.0.0.5", action.ip());
        assertEquals("admin", action.actor());
        assertEquals("human review", action.reason());
        assertFalse(action.automatic());
        assertEquals(base.plus(Duration.ofMinutes(30)), action.expiresAt());

        assertTrue(service.isBlocked("10.0.0.5"));
        assertFalse(service.admit(from("10.0.0.5")));
        assertTrue(service.admit(from("10.0.0.6")));
        assertEquals(1, service.status().droppedEvents());
        assertEquals(1, service.status().blocked());
        assertEquals(1, service.active().size());

        assertTrue(service.release(" 10.0.0.5 "));
        assertFalse(service.release("10.0.0.5"));
        assertTrue(service.admit(from("10.0.0.5")));
    }

    @Test
    @DisplayName("Enforcement off records the block but keeps traffic flowing")
    void rehearsalModeDoesNotDrop() {
        MutableClock clock = new MutableClock(base);
        ContainmentService service = service(clock, true, false, false, 1_440);
        service.contain("10.0.0.5", 10, "rehearsal", "admin");
        assertTrue(service.isBlocked("10.0.0.5"));
        assertTrue(service.admit(from("10.0.0.5")), "without enforcement nothing is dropped");
        assertEquals(0, service.status().droppedEvents());
        assertEquals(1, service.status().blocked());
    }

    @Test
    @DisplayName("Every action expires; the expiry is counted")
    void actionsExpire() {
        MutableClock clock = new MutableClock(base);
        ContainmentService service = service(clock, true, false, true, 1_440);
        service.contain("10.0.0.5", 30, "window", "admin");

        clock.advance(Duration.ofMinutes(31));
        assertFalse(service.isBlocked("10.0.0.5"));
        assertTrue(service.admit(from("10.0.0.5")));
        assertEquals(1, service.status().expiredActions());
        assertEquals(0, service.status().blocked());
    }

    @Test
    @DisplayName("Duration is clamped and a blank address is rejected")
    void durationIsClamped() {
        MutableClock clock = new MutableClock(base);
        ContainmentService service = service(clock, true, false, false, 60);
        ContainmentService.Action longAction = service.contain("10.0.0.5", 10_000, null, null);
        assertEquals(base.plus(Duration.ofMinutes(60)), longAction.expiresAt());
        assertEquals("", longAction.reason());
        assertEquals("", longAction.actor());

        ContainmentService.Action shortAction = service.contain("10.0.0.6", 0, "zero", "admin");
        assertEquals(base.plus(Duration.ofMinutes(1)), shortAction.expiresAt());

        assertThrows(IllegalArgumentException.class, () -> service.contain("  ", 5, "blank", "admin"));
        assertTrue(service.active().size() >= 2);
    }

    @Test
    @DisplayName("Automatic containment only reacts at or above the configured severity")
    void automaticContainmentRespectsSeverity() {
        MutableClock clock = new MutableClock(base);
        ContainmentService service = service(clock, true, true, true, 1_440);
        AlertFactory factory = new AlertFactory();

        Alert low = factory.create(Severity.LOW, AttackType.PORT_SCAN, "10.0.0.5", "10.0.0.9",
                "Detector", "noise", base);
        service.onAlert(low);
        assertFalse(service.isBlocked("10.0.0.5"));

        Alert critical = factory.create(Severity.CRITICAL, AttackType.DATA_TRANSFER, "10.0.0.7",
                "198.51.100.9", "Detector", "exfiltration", base.plusSeconds(1));
        service.onAlert(critical);
        assertTrue(service.isBlocked("10.0.0.7"));
        assertEquals(1, service.status().automaticActions());
        ContainmentService.Action action = service.active().get(0);
        assertTrue(action.automatic());
        assertEquals("system", action.actor());
        assertTrue(action.reason().contains("Detector"));

        service.onAlert(critical);
        assertEquals(1, service.status().automaticActions(), "an active block is not duplicated");

        List<ContainmentService.Action> active = service.active();
        assertEquals(1, active.size());
    }

    @Test
    @DisplayName("reset clears the list and every counter")
    void resetClearsState() {
        MutableClock clock = new MutableClock(base);
        ContainmentService service = service(clock, true, true, true, 1_440);
        service.contain("10.0.0.5", 10, "manual", "admin");
        service.onAlert(new AlertFactory().create(Severity.CRITICAL, AttackType.DOS_FLOOD,
                "10.0.0.7", "10.0.0.9", "Detector", "flood", base));
        assertTrue(service.status().blocked() >= 1);

        service.reset();
        ContainmentService.Status status = service.status();
        assertEquals(0, status.blocked());
        assertEquals(0, status.droppedEvents());
        assertEquals(0, status.automaticActions());
        assertEquals(0, status.expiredActions());
        assertTrue(service.active().isEmpty());
    }
}
