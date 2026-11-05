package pk.ooad.ntd.simulation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Server;
import pk.ooad.ntd.domain.TopologyLoader;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.BlockingQueue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrafficSimulatorTest {

    @Test
    @DisplayName("Deterministic output: Running two instances with one seed produces identical event sequence")
    void testSameSeedProducesExactSameSequence() {
        long seed = 987654321L;
        Network network1 = TopologyLoader.loadSample();
        Network network2 = TopologyLoader.loadSample();
        Clock fixedClock = Clock.fixed(Instant.parse("2026-01-01T12:00:00Z"), ZoneOffset.UTC);

        TrafficSimulator sim1 = new TrafficSimulator(network1, fixedClock, new Random(seed));
        TrafficSimulator sim2 = new TrafficSimulator(network2, fixedClock, new Random(seed));

        int eventCount = 50;
        List<NetworkEvent> events1 = new ArrayList<>();
        List<NetworkEvent> events2 = new ArrayList<>();

        for (int i = 0; i < eventCount; i++) {
            events1.add(sim1.generateNormalEvent());
            events2.add(sim2.generateNormalEvent());
        }

        assertEquals(eventCount, events1.size());
        assertEquals(eventCount, events2.size());

        for (int i = 0; i < eventCount; i++) {
            NetworkEvent e1 = events1.get(i);
            NetworkEvent e2 = events2.get(i);

            assertEquals(e1.id(), e2.id(), "Event ID must match at index " + i);
            assertEquals(e1.timestamp(), e2.timestamp(), "Timestamp must match at index " + i);
            assertEquals(e1.sourceIp(), e2.sourceIp(), "Source IP must match at index " + i);
            assertEquals(e1.destIp(), e2.destIp(), "Dest IP must match at index " + i);
            assertEquals(e1.port(), e2.port(), "Port must match at index " + i);
            assertEquals(e1.bytes(), e2.bytes(), "Byte count must match at index " + i);
            assertEquals(e1.type(), e2.type(), "Event type must match at index " + i);
            assertEquals(e1.success(), e2.success(), "Success flag must match at index " + i);
            assertEquals(e1.payload(), e2.payload(), "Payload must match at index " + i);
            assertEquals(e1, e2, "NetworkEvent value object must be completely equal at index " + i);
        }
    }

    @Test
    @DisplayName("Different seed produces different sequence of events")
    void testDifferentSeedProducesDifferentSequence() {
        Network network = TopologyLoader.loadSample();
        Clock fixedClock = Clock.fixed(Instant.parse("2026-01-01T12:00:00Z"), ZoneOffset.UTC);

        TrafficSimulator sim1 = new TrafficSimulator(network, fixedClock, new Random(11111L));
        TrafficSimulator sim2 = new TrafficSimulator(network, fixedClock, new Random(99999L));

        int eventCount = 20;
        List<NetworkEvent> events1 = new ArrayList<>();
        List<NetworkEvent> events2 = new ArrayList<>();

        for (int i = 0; i < eventCount; i++) {
            events1.add(sim1.generateNormalEvent());
            events2.add(sim2.generateNormalEvent());
        }

        boolean foundDifference = false;
        for (int i = 0; i < eventCount; i++) {
            NetworkEvent e1 = events1.get(i);
            NetworkEvent e2 = events2.get(i);
            if (!e1.sourceIp().equals(e2.sourceIp()) ||
                !e1.destIp().equals(e2.destIp()) ||
                e1.port() != e2.port() ||
                e1.bytes() != e2.bytes()) {
                foundDifference = true;
                break;
            }
        }
        assertTrue(foundDifference, "Different seeds must produce different event attributes");
    }

    @Test
    @DisplayName("injectAttack: Queues attack events and updates ground truth for all AttackTypes")
    void testInjectAttackAllTypes() {
        TrafficSimulator sim = new TrafficSimulator(TopologyLoader.loadSample(), 42L);
        BlockingQueue<NetworkEvent> queue = sim.getEventQueue();

        assertEquals(0, queue.size());
        assertEquals(0, sim.getGroundTruth().size());

        for (AttackType type : AttackType.values()) {
            int queueBefore = queue.size();
            int groundTruthBefore = sim.getGroundTruth().size();

            sim.injectAttack(type, "10.0.0.100", "10.0.0.1");

            assertTrue(queue.size() > queueBefore, "Events must be placed in queue for " + type);
            assertEquals(groundTruthBefore + 1, sim.getGroundTruth().size());

            AttackRecord record = sim.getGroundTruth().get(sim.getGroundTruth().size() - 1);
            assertEquals(type, record.getType());
            assertEquals("10.0.0.100", record.getSource());
            assertEquals("10.0.0.1", record.getTarget());
            assertNotNull(record.getStartTime());
        }
    }

    @Test
    @DisplayName("Negative: injectAttack with null AttackType throws NullPointerException")
    void testInjectAttackNullValidation() {
        TrafficSimulator sim = new TrafficSimulator(42L);
        assertThrows(NullPointerException.class, () ->
            sim.injectAttack(null, "10.0.0.1", "10.0.0.2")
        );
    }

    @Test
    @DisplayName("Lifecycle: start, stop, reset, and setAutoMode")
    void testLifecycleAndAutoMode() throws InterruptedException {
        TrafficSimulator sim = new TrafficSimulator(42L);
        assertFalse(sim.isRunning());
        assertFalse(sim.isAutoMode());

        sim.setAutoMode(true);
        assertTrue(sim.isAutoMode());

        sim.start();
        assertTrue(sim.isRunning());

        // Wait briefly for worker thread to produce events
        long deadline = System.currentTimeMillis() + 1000;
        while (sim.getEventQueue().isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        assertFalse(sim.getEventQueue().isEmpty(), "Worker thread should push events in auto mode");

        sim.stop();
        assertFalse(sim.isRunning());

        // Reset clears queue and ground truth
        sim.injectAttack(AttackType.PORT_SCAN, "1.1.1.1", "2.2.2.2");
        assertFalse(sim.getEventQueue().isEmpty());
        assertFalse(sim.getGroundTruth().isEmpty());

        sim.reset();
        assertEquals(0, sim.getEventQueue().size());
        assertEquals(0, sim.getGroundTruth().size());
    }

    @Test
    @DisplayName("Edge case: generateNormalEvent with empty or null network")
    void testEmptyNetworkFallback() {
        TrafficSimulator nullNetSim = new TrafficSimulator(null, 42L);
        NetworkEvent event = nullNetSim.generateNormalEvent();
        assertNotNull(event);
        assertNotNull(event.sourceIp());
        assertNotNull(event.destIp());

        Network singleNodeNet = new Network();
        singleNodeNet.addAsset(new Server("s1", "Lone Server", "10.0.0.1", 1));
        TrafficSimulator singleSim = new TrafficSimulator(singleNodeNet, 42L);
        NetworkEvent event2 = singleSim.generateNormalEvent();
        assertNotNull(event2);
    }
}

