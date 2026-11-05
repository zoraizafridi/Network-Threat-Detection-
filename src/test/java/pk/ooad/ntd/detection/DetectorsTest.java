package pk.ooad.ntd.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectorsTest {

    private final Instant baseTime = Instant.parse("2026-11-05T12:00:00Z");

    @Test
    @DisplayName("SignatureDetector: Detects bad IP, bad port, and malicious payload; normal raises none")
    void testSignatureDetector() {
        SignatureDetector detector = new SignatureDetector();

        // Normal event raises NO alert
        NetworkEvent normal = new NetworkEvent(1L, baseTime, "10.0.0.1", "10.0.0.2", 80, 500L, EventType.REQUEST, true, "NORMAL_PAYLOAD");
        assertTrue(detector.analyze(normal).isEmpty(), "Normal event must not trigger signature alert");

        // Bad IP
        NetworkEvent badIpEvent = new NetworkEvent(2L, baseTime, "198.51.100.4", "10.0.0.2", 80, 500L, EventType.REQUEST, true, "GET /");
        Optional<Alert> alertIp = detector.analyze(badIpEvent);
        assertTrue(alertIp.isPresent(), "Bad IP must trigger signature alert");

        // Bad Port
        NetworkEvent badPortEvent = new NetworkEvent(3L, baseTime, "10.0.0.1", "10.0.0.2", 31337, 500L, EventType.REQUEST, true, "GET /");
        Optional<Alert> alertPort = detector.analyze(badPortEvent);
        assertTrue(alertPort.isPresent(), "Bad port must trigger signature alert");

        // Payload match
        NetworkEvent floodEvent = new NetworkEvent(4L, baseTime, "10.0.0.1", "10.0.0.2", 80, 500L, EventType.REQUEST, true, "DOS_FLOOD_PAYLOAD");
        Optional<Alert> alertFlood = detector.analyze(floodEvent);
        assertTrue(alertFlood.isPresent());
        assertEquals(AttackType.DOS_FLOOD, alertFlood.get().getAttackType());

        detector.reset();
    }

    @Test
    @DisplayName("RateThresholdDetector: Detects failed login bursts; normal traffic raises none")
    void testRateThresholdDetector() {
        RateThresholdDetector detector = new RateThresholdDetector("RateThresholdDetector", 60, 3);

        // Normal events raise NO alert
        for (int i = 0; i < 10; i++) {
            NetworkEvent normal = new NetworkEvent(i, baseTime.plusSeconds(i), "10.0.0.1", "10.0.0.2", 80, 500L, EventType.REQUEST, true, "OK");
            assertTrue(detector.analyze(normal).isEmpty());
        }

        // Successful logins do not trigger alert
        for (int i = 0; i < 5; i++) {
            NetworkEvent successLogin = new NetworkEvent(100 + i, baseTime.plusSeconds(i), "10.0.0.1", "10.0.0.2", 22, 100L, EventType.LOGIN_ATTEMPT, true, "LOGIN_OK");
            assertTrue(detector.analyze(successLogin).isEmpty());
        }

        // Failed logins up to threshold (3) -> no alert
        for (int i = 1; i <= 3; i++) {
            NetworkEvent fail = new NetworkEvent(200 + i, baseTime.plusSeconds(i), "10.0.0.50", "10.0.0.2", 22, 100L, EventType.LOGIN_ATTEMPT, false, "FAIL");
            assertTrue(detector.analyze(fail).isEmpty());
        }

        // 4th failure (> 3) -> alert
        NetworkEvent fourthFail = new NetworkEvent(204L, baseTime.plusSeconds(4), "10.0.0.50", "10.0.0.2", 22, 100L, EventType.LOGIN_ATTEMPT, false, "FAIL");
        Optional<Alert> alert = detector.analyze(fourthFail);
        assertTrue(alert.isPresent(), "Failed logins exceeding maxFailures must trigger alert");
        assertEquals(AttackType.BRUTE_FORCE, alert.get().getAttackType());

        // reset() clears state
        detector.reset();
        assertEquals(0, detector.getFailuresBySource().size());
        assertTrue(detector.analyze(fourthFail).isEmpty(), "After reset, state must be cleared and under threshold");
    }

    @Test
    @DisplayName("PortScanDetector: Detects distinct port/host probes; normal traffic raises none")
    void testPortScanDetector() {
        PortScanDetector detector = new PortScanDetector("PortScanDetector", 60, 3, 3);

        // Normal traffic (repeated access to ports 80 and 443) -> no alert
        for (int i = 0; i < 10; i++) {
            int port = (i % 2 == 0) ? 80 : 443;
            NetworkEvent normal = new NetworkEvent(i, baseTime.plusSeconds(i), "10.0.0.1", "10.0.0.2", port, 200L, EventType.REQUEST, true, "GET");
            assertTrue(detector.analyze(normal).isEmpty());
        }

        // Probing 4 distinct ports (> 3) -> raises alert
        detector.analyze(new NetworkEvent(101L, baseTime.plusSeconds(1), "10.0.0.99", "10.0.0.2", 21, 40L, EventType.CONNECT, false, "SYN"));
        detector.analyze(new NetworkEvent(102L, baseTime.plusSeconds(2), "10.0.0.99", "10.0.0.2", 22, 40L, EventType.CONNECT, false, "SYN"));
        detector.analyze(new NetworkEvent(103L, baseTime.plusSeconds(3), "10.0.0.99", "10.0.0.2", 23, 40L, EventType.CONNECT, false, "SYN"));

        NetworkEvent fourthPort = new NetworkEvent(104L, baseTime.plusSeconds(4), "10.0.0.99", "10.0.0.2", 25, 40L, EventType.CONNECT, false, "SYN");
        Optional<Alert> alert = detector.analyze(fourthPort);
        assertTrue(alert.isPresent(), "Scanning 4 distinct ports when max is 3 must raise alert");
        assertEquals(AttackType.PORT_SCAN, alert.get().getAttackType());

        // reset() clears touches
        detector.reset();
        assertEquals(0, detector.getTouches().size());
    }

    @Test
    @DisplayName("AnomalyDetector: No alert during warmup; alerts on high z-score and does not update baseline")
    void testAnomalyDetectorWarmupAndAnomaly() {
        AnomalyDetector detector = new AnomalyDetector("AnomalyDetector", 3.0, 5);

        // 1. Warmup phase: first 5 events (mean ~ 500, std ~ 50) must not alert
        long[] baselineBytes = {500L, 520L, 480L, 510L, 490L};
        for (int i = 0; i < 5; i++) {
            NetworkEvent warmupEvent = new NetworkEvent(i, baseTime.plusSeconds(i), "10.0.0.10", "10.0.0.2", 80, baselineBytes[i], EventType.DATA_TRANSFER, true, "OK");
            Optional<Alert> opt = detector.analyze(warmupEvent);
            assertTrue(opt.isEmpty(), "AnomalyDetector must not alert during warmup count (" + i + ")");
        }

        // Post-warmup normal event -> no alert
        NetworkEvent normalPostWarmup = new NetworkEvent(6L, baseTime.plusSeconds(6), "10.0.0.10", "10.0.0.2", 80, 505L, EventType.DATA_TRANSFER, true, "OK");
        assertTrue(detector.analyze(normalPostWarmup).isEmpty());

        RunningStats statsBeforeAttack = detector.getStats().get("10.0.0.10");
        long countBefore = statsBeforeAttack.getCount();
        double meanBefore = statsBeforeAttack.getMean();

        // 2. Anomaly: 1,000,000 bytes (z-score >> 3.0) -> must alert
        NetworkEvent exfiltration = new NetworkEvent(7L, baseTime.plusSeconds(7), "10.0.0.10", "10.0.0.2", 443, 1_000_000L, EventType.DATA_TRANSFER, true, "DUMP");
        Optional<Alert> alert = detector.analyze(exfiltration);
        assertTrue(alert.isPresent(), "Extreme byte volume must trigger anomaly alert");
        assertEquals(AttackType.DATA_TRANSFER, alert.get().getAttackType());

        // 3. No baseline update on flagged values: stats count and mean must remain unchanged!
        assertEquals(countBefore, statsBeforeAttack.getCount(), "Baseline count must not increase on flagged anomaly");
        assertEquals(meanBefore, statsBeforeAttack.getMean(), "Baseline mean must not be updated on flagged anomaly");

        // 4. reset() clears stats
        detector.reset();
        assertEquals(0, detector.getStats().size(), "reset() must clear all host statistics");
    }
}

