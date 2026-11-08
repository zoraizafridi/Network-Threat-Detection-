package pk.ooad.ntd.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.simulation.TrafficSimulator;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectionEngineTest {

    @Test
    @DisplayName("(1) Seeded TrafficSimulator running normal traffic only raises ZERO alerts")
    void testNormalTrafficRaisesZeroAlerts() {
        Network network = TopologyLoader.loadSample();
        TrafficSimulator sim = new TrafficSimulator(network, 4242L);

        BlockingQueue<NetworkEvent> queue = new LinkedBlockingQueue<>();
        AlertBus bus = new AlertBus();
        List<Alert> alertsReceived = new CopyOnWriteArrayList<>();
        bus.subscribe(alertsReceived::add);

        DetectionEngine engine = new DetectionEngine(queue, bus, 5);
        DetectorFactory factory = new DetectorFactory();
        for (Detector d : factory.createAll()) {
            engine.addDetector(d);
        }

        engine.start();

        int normalEventCount = 100;
        for (int i = 0; i < normalEventCount; i++) {
            queue.offer(sim.generateNormalEvent());
        }

        // Wait for queue to be drained using timed polling check
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (!queue.isEmpty() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }

        // stop() cleanly finishes current processing and terminates worker thread
        engine.stop();
        assertFalse(engine.isRunning());

        assertEquals(0, alertsReceived.size(), "Normal traffic must raise exactly zero alerts");
    }

    @Test
    @DisplayName("(2) Each of the four attacks injected into a seeded simulator raises at least one alert")
    void testInjectedAttacksRaiseAlerts() throws InterruptedException {
        Network network = TopologyLoader.loadSample();
        TrafficSimulator sim = new TrafficSimulator(network, 12345L);

        for (AttackType attackType : AttackType.values()) {
            BlockingQueue<NetworkEvent> queue = new LinkedBlockingQueue<>();
            AlertBus bus = new AlertBus();
            List<Alert> alerts = new CopyOnWriteArrayList<>();
            CountDownLatch alertLatch = new CountDownLatch(1);

            bus.subscribe(a -> {
                alerts.add(a);
                alertLatch.countDown();
            });

            DetectionEngine engine = new DetectionEngine(queue, bus, 0); // 0 cooldown for direct attack test
            engine.addDetector(new SignatureDetector());
            engine.addDetector(new RateThresholdDetector());
            engine.addDetector(new PortScanDetector());
            engine.addDetector(new AnomalyDetector("AnomalyDetector", 3.0, 5));

            engine.start();

            String srcIp = "10.0.0.100";
            String dstIp = "10.0.0.1";
            Instant now = Instant.parse("2026-11-05T12:00:00Z");

            // For AnomalyDetector warmup on DATA_TRANSFER, provide 5 baseline normal events first
            if (attackType == AttackType.DATA_TRANSFER) {
                long[] warmupBytes = {480L, 510L, 490L, 520L, 500L};
                for (int i = 0; i < warmupBytes.length; i++) {
                    queue.offer(new NetworkEvent(i + 1, now.plusSeconds(i), srcIp, dstIp, 80, warmupBytes[i], EventType.DATA_TRANSFER, true, "OK"));
                }
            }

            sim.injectAttack(attackType, srcIp, dstIp);

            BlockingQueue<NetworkEvent> simQueue = sim.getEventQueue();
            while (!simQueue.isEmpty()) {
                NetworkEvent e = simQueue.poll();
                if (e != null) {
                    queue.offer(e);
                }
            }

            boolean alertReceived = alertLatch.await(3, TimeUnit.SECONDS);
            engine.stop();

            assertTrue(alertReceived, "Injected attack " + attackType + " must raise at least one alert");
            assertFalse(alerts.isEmpty());
            assertEquals(attackType, alerts.get(0).getAttackType(), "Alert attack type must match injected attack");
        }
    }

    @Test
    @DisplayName("(3) Cooldown suppresses repeat alerts from the same source")
    void testCooldownSuppressesRepeatAlerts() throws InterruptedException {
        BlockingQueue<NetworkEvent> queue = new LinkedBlockingQueue<>();
        AlertBus bus = new AlertBus();
        List<Alert> alerts = new CopyOnWriteArrayList<>();

        CountDownLatch firstSourceLatch = new CountDownLatch(1);
        CountDownLatch secondSourceLatch = new CountDownLatch(1);

        bus.subscribe(alert -> {
            alerts.add(alert);
            if ("10.0.0.100".equals(alert.getSourceIp())) {
                firstSourceLatch.countDown();
            } else if ("10.0.0.200".equals(alert.getSourceIp())) {
                secondSourceLatch.countDown();
            }
        });

        // Cooldown of 30 seconds
        DetectionEngine engine = new DetectionEngine(queue, bus, 30);
        engine.addDetector(new SignatureDetector());
        engine.start();

        Instant t0 = Instant.parse("2026-11-05T12:00:00Z");

        // First attack from source A (triggers alert 1)
        queue.offer(new NetworkEvent(1L, t0, "10.0.0.100", "10.0.0.1", 80, 500L, EventType.REQUEST, true, "DOS_FLOOD_PAYLOAD"));
        assertTrue(firstSourceLatch.await(3, TimeUnit.SECONDS), "First alert from source A must be published");

        // Repeat attack from source A within cooldown (timestamp t0 + 5s < t0 + 30s) -> must be SUPPRESSED
        queue.offer(new NetworkEvent(2L, t0.plusSeconds(5), "10.0.0.100", "10.0.0.1", 80, 500L, EventType.REQUEST, true, "DOS_FLOOD_PAYLOAD"));
        queue.offer(new NetworkEvent(3L, t0.plusSeconds(10), "10.0.0.100", "10.0.0.1", 80, 500L, EventType.REQUEST, true, "DOS_FLOOD_PAYLOAD"));

        // Attack from source B (different source) -> must NOT be suppressed by source A's cooldown
        queue.offer(new NetworkEvent(4L, t0.plusSeconds(15), "10.0.0.200", "10.0.0.1", 80, 500L, EventType.REQUEST, true, "DOS_FLOOD_PAYLOAD"));

        // Wait for source B to be processed (due to FIFO ordering, source A events are processed first)
        assertTrue(secondSourceLatch.await(3, TimeUnit.SECONDS), "Alert from different source B must be published");

        engine.stop();

        long sourceACount = alerts.stream().filter(a -> "10.0.0.100".equals(a.getSourceIp())).count();
        long sourceBCount = alerts.stream().filter(a -> "10.0.0.200".equals(a.getSourceIp())).count();

        assertEquals(1, sourceACount, "Repeat alerts from source A within cooldown must be suppressed to exactly 1");
        assertEquals(1, sourceBCount, "Alert from source B must be published");
    }

    @Test
    @DisplayName("Lifecycle: stop cleanly ends worker thread and reset clears state")
    void testEngineLifecycle() {
        BlockingQueue<NetworkEvent> queue = new LinkedBlockingQueue<>();
        AlertBus bus = new AlertBus();
        DetectionEngine engine = new DetectionEngine(queue, bus, 10);
        engine.addDetector(new SignatureDetector());

        assertFalse(engine.isRunning());
        engine.start();
        assertTrue(engine.isRunning());

        engine.stop();
        assertFalse(engine.isRunning());

        engine.reset();
        assertEquals(0, engine.getLastAlertAt().size());
    }
}
