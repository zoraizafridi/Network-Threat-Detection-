package pk.ooad.ntd.detection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EventObserverTest {

    @Test
    @DisplayName("An event observer sees every event and a throwing observer cannot stop detection")
    void observersSeeEventsWithoutBreakingDetection() throws InterruptedException {
        BlockingQueue<NetworkEvent> queue = new LinkedBlockingQueue<>();
        AlertBus bus = new AlertBus();
        CountDownLatch alertLatch = new CountDownLatch(1);
        AtomicInteger observed = new AtomicInteger();
        bus.subscribe(alert -> alertLatch.countDown());

        DetectionEngine engine = new DetectionEngine(queue, bus, 0);
        engine.addDetector(new SignatureDetector());
        engine.addEventObserver(event -> observed.incrementAndGet());
        engine.addEventObserver(event -> {
            throw new IllegalStateException("observer fault");
        });
        engine.addEventObserver(null); // must be ignored, not registered
        engine.start();

        try {
            queue.offer(new NetworkEvent(1L, Instant.parse("2026-11-05T12:00:00Z"), "10.0.0.100", "10.0.0.1",
                    80, 500L, EventType.REQUEST, true, "DOS_FLOOD_PAYLOAD", false));
            assertTrue(alertLatch.await(3, TimeUnit.SECONDS),
                    "detection must still publish an alert after an observer throws");
        } finally {
            engine.stop();
        }

        assertEquals(1, observed.get(), "the healthy observer must see the event");
        assertEquals(2, engine.getEventObservers().size(), "a null observer must not be registered");
    }
}
