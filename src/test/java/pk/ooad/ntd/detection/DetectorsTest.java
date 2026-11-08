package pk.ooad.ntd.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.util.ConfigManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;

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

        NetworkEvent normal = new NetworkEvent(1L, baseTime, "10.0.0.1", "10.0.0.2", 80, 500L, EventType.REQUEST, true, "NORMAL_PAYLOAD");
        assertTrue(detector.analyze(normal).isEmpty(), "Normal event must not trigger signature alert");

        NetworkEvent badIpEvent = new NetworkEvent(2L, baseTime, "198.51.100.4", "10.0.0.2", 80, 500L, EventType.REQUEST, true, "GET /");
        Optional<Alert> alertIp = detector.analyze(badIpEvent);
        assertTrue(alertIp.isPresent(), "Bad IP must trigger signature alert");

        NetworkEvent badPortEvent = new NetworkEvent(3L, baseTime, "10.0.0.1", "10.0.0.2", 31337, 500L, EventType.REQUEST, true, "GET /");
        Optional<Alert> alertPort = detector.analyze(badPortEvent);
        assertTrue(alertPort.isPresent(), "Bad port must trigger signature alert");

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

        for (int i = 0; i < 10; i++) {
            NetworkEvent normal = new NetworkEvent(i, baseTime.plusSeconds(i), "10.0.0.1", "10.0.0.2", 80, 500L, EventType.REQUEST, true, "OK");
            assertTrue(detector.analyze(normal).isEmpty());
        }

        for (int i = 0; i < 5; i++) {
            NetworkEvent successLogin = new NetworkEvent(100 + i, baseTime.plusSeconds(i), "10.0.0.1", "10.0.0.2", 22, 100L, EventType.LOGIN_ATTEMPT, true, "LOGIN_OK");
            assertTrue(detector.analyze(successLogin).isEmpty());
        }

        for (int i = 1; i <= 3; i++) {
            NetworkEvent fail = new NetworkEvent(200 + i, baseTime.plusSeconds(i), "10.0.0.50", "10.0.0.2", 22, 100L, EventType.LOGIN_ATTEMPT, false, "FAIL");
            assertTrue(detector.analyze(fail).isEmpty());
        }

        NetworkEvent fourthFail = new NetworkEvent(204L, baseTime.plusSeconds(4), "10.0.0.50", "10.0.0.2", 22, 100L, EventType.LOGIN_ATTEMPT, false, "FAIL");
        Optional<Alert> alert = detector.analyze(fourthFail);
        assertTrue(alert.isPresent(), "Failed logins exceeding maxFailures must trigger alert");
        assertEquals(AttackType.BRUTE_FORCE, alert.get().getAttackType());

        detector.reset();
        assertEquals(0, detector.getFailuresBySource().size());
        assertTrue(detector.analyze(fourthFail).isEmpty(), "After reset, state must be cleared and under threshold");
    }

    @Test
    @DisplayName("PortScanDetector: Detects distinct port/host probes; normal traffic raises none")
    void testPortScanDetector() {
        PortScanDetector detector = new PortScanDetector("PortScanDetector", 60, 3, 3);

        for (int i = 0; i < 10; i++) {
            int port = (i % 2 == 0) ? 80 : 443;
            NetworkEvent normal = new NetworkEvent(i, baseTime.plusSeconds(i), "10.0.0.1", "10.0.0.2", port, 200L, EventType.REQUEST, true, "GET");
            assertTrue(detector.analyze(normal).isEmpty());
        }

        detector.analyze(new NetworkEvent(101L, baseTime.plusSeconds(1), "10.0.0.99", "10.0.0.2", 21, 40L, EventType.CONNECT, false, "SYN"));
        detector.analyze(new NetworkEvent(102L, baseTime.plusSeconds(2), "10.0.0.99", "10.0.0.2", 22, 40L, EventType.CONNECT, false, "SYN"));
        detector.analyze(new NetworkEvent(103L, baseTime.plusSeconds(3), "10.0.0.99", "10.0.0.2", 23, 40L, EventType.CONNECT, false, "SYN"));

        NetworkEvent fourthPort = new NetworkEvent(104L, baseTime.plusSeconds(4), "10.0.0.99", "10.0.0.2", 25, 40L, EventType.CONNECT, false, "SYN");
        Optional<Alert> alert = detector.analyze(fourthPort);
        assertTrue(alert.isPresent(), "Scanning 4 distinct ports when max is 3 must raise alert");
        assertEquals(AttackType.PORT_SCAN, alert.get().getAttackType());

        detector.reset();
        assertEquals(0, detector.getTouches().size());
    }

    @Test
    @DisplayName("AnomalyDetector: No alert during warmup; alerts on high z-score and does not update baseline")
    void testAnomalyDetectorWarmupAndAnomaly() {
        AnomalyDetector detector = new AnomalyDetector("AnomalyDetector", 3.0, 5);

        long[] baselineBytes = {500L, 520L, 480L, 510L, 490L};
        for (int i = 0; i < 5; i++) {
            NetworkEvent warmupEvent = new NetworkEvent(i, baseTime.plusSeconds(i), "10.0.0.10", "10.0.0.2", 80, baselineBytes[i], EventType.DATA_TRANSFER, true, "OK");
            Optional<Alert> opt = detector.analyze(warmupEvent);
            assertTrue(opt.isEmpty(), "AnomalyDetector must not alert during warmup count (" + i + ")");
        }

        NetworkEvent normalPostWarmup = new NetworkEvent(6L, baseTime.plusSeconds(6), "10.0.0.10", "10.0.0.2", 80, 505L, EventType.DATA_TRANSFER, true, "OK");
        assertTrue(detector.analyze(normalPostWarmup).isEmpty());

        RunningStats statsBeforeAttack = detector.getStats().get("10.0.0.10");
        long countBefore = statsBeforeAttack.getCount();
        double meanBefore = statsBeforeAttack.getMean();

        NetworkEvent exfiltration = new NetworkEvent(7L, baseTime.plusSeconds(7), "10.0.0.10", "10.0.0.2", 443, 1_000_000L, EventType.DATA_TRANSFER, true, "DUMP");
        Optional<Alert> alert = detector.analyze(exfiltration);
        assertTrue(alert.isPresent(), "Extreme byte volume must trigger anomaly alert");
        assertEquals(AttackType.DATA_TRANSFER, alert.get().getAttackType());

        assertEquals(countBefore, statsBeforeAttack.getCount(), "Baseline count must not increase on flagged anomaly");
        assertEquals(meanBefore, statsBeforeAttack.getMean(), "Baseline mean must not be updated on flagged anomaly");

        detector.reset();
        assertEquals(0, detector.getStats().size(), "reset() must clear all host statistics");
    }

        @Test
        @DisplayName("No-argument detection components use configured threshold values")
        void noArgumentDetectorsReadThresholdsFromConfiguration() throws IOException {
        Path configFile = Files.createTempFile("ntd-detection-config", ".properties");
        try {
            Files.writeString(configFile, """
                detection.cooldownSeconds=17
                detection.rate.windowSeconds=9
                detection.rate.maxFailures=1
                detection.portScan.windowSeconds=8
                detection.portScan.maxDistinctPorts=1
                detection.portScan.maxDistinctHosts=1
                detection.anomaly.zThreshold=0.1
                detection.anomaly.warmupCount=2
                detection.signature.badIps=198.51.100.77
                detection.signature.badPorts=65000
                detection.signature.payloadPatterns=CONFIG_MARKER
                """);
            ConfigManager.getInstance().load(configFile.toString());

            RateThresholdDetector rateDetector = new RateThresholdDetector();
            assertEquals(9, rateDetector.getWindowSeconds());
            assertEquals(1, rateDetector.getMaxFailures());
            rateDetector.analyze(new NetworkEvent(1, baseTime, "10.0.0.77", "10.0.0.2", 22,
                20, EventType.LOGIN_ATTEMPT, false, "FAIL"));
            assertTrue(rateDetector.analyze(new NetworkEvent(2, baseTime.plusSeconds(1), "10.0.0.77",
                "10.0.0.2", 22, 20, EventType.LOGIN_ATTEMPT, false, "FAIL")).isPresent());

            PortScanDetector portDetector = new PortScanDetector();
            assertEquals(8, portDetector.getWindowSeconds());
            assertEquals(1, portDetector.getMaxDistinctPorts());
            assertEquals(1, portDetector.getMaxDistinctHosts());
            portDetector.analyze(new NetworkEvent(3, baseTime, "10.0.0.78", "10.0.0.2", 21,
                20, EventType.CONNECT, false, "SYN"));
            assertTrue(portDetector.analyze(new NetworkEvent(4, baseTime.plusSeconds(1), "10.0.0.78",
                "10.0.0.3", 22, 20, EventType.CONNECT, false, "SYN")).isPresent());

            AnomalyDetector anomalyDetector = new AnomalyDetector();
            assertEquals(0.1, anomalyDetector.getZThreshold());
            assertEquals(2, anomalyDetector.getWarmupCount());
            anomalyDetector.analyze(new NetworkEvent(5, baseTime, "10.0.0.79", "10.0.0.2", 80,
                100, EventType.DATA_TRANSFER, true, "OK"));
            anomalyDetector.analyze(new NetworkEvent(6, baseTime.plusSeconds(1), "10.0.0.79", "10.0.0.2",
                80, 101, EventType.DATA_TRANSFER, true, "OK"));
            assertTrue(anomalyDetector.analyze(new NetworkEvent(7, baseTime.plusSeconds(2), "10.0.0.79",
                "10.0.0.2", 80, 10_000, EventType.DATA_TRANSFER, true, "OK")).isPresent());

            SignatureDetector signatureDetector = new SignatureDetector();
            assertTrue(signatureDetector.getBadIps().contains("198.51.100.77"));
            assertTrue(signatureDetector.getBadPorts().contains(65000));
            assertTrue(signatureDetector.analyze(new NetworkEvent(8, baseTime, "10.0.0.80", "10.0.0.2",
                80, 100, EventType.REQUEST, true, "CONFIG_MARKER")).isPresent());

            DetectionEngine engine = new DetectionEngine(new LinkedBlockingQueue<>(), new AlertBus());
            assertEquals(17, engine.getCooldownSeconds());
        } finally {
            ConfigManager.getInstance().reload();
            Files.deleteIfExists(configFile);
        }
        }
}
