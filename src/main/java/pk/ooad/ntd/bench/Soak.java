package pk.ooad.ntd.bench;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.detection.DetectionEngine;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.persistence.PersistenceStatus;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.function.LongSupplier;

public final class Soak {

    public record Dur(double mean, double p50, double p95, double p99, double max) {
        public static final Dur ZERO = new Dur(0.0, 0.0, 0.0, 0.0, 0.0);

        static Dur from(long[] sortedNanos) {
            if (sortedNanos.length == 0) {
                return ZERO;
            }
            long total = 0L;
            for (long sample : sortedNanos) {
                total += sample;
            }
            return new Dur(total / 1000.0 / sortedNanos.length,
                    percentile(sortedNanos, 0.50), percentile(sortedNanos, 0.95),
                    percentile(sortedNanos, 0.99), sortedNanos[sortedNanos.length - 1] / 1000.0);
        }

        public boolean isOrdered() {
            return p50 <= p95 && p95 <= p99 && p99 <= max;
        }

        public String line() {
            return String.format(Locale.ROOT,
                    "mean %.2f us, p50 %.2f us, p95 %.2f us, p99 %.2f us, max %.2f us",
                    mean, p50, p95, p99, max);
        }
    }

    public record Report(int requestedSeconds, long elapsedMillis, double targetRate,
                         long offered, long processed, long dropped, long detected, long alerts,
                         long storeRows, int maxQueueDepth, double meanQueueDepth,
                         long samples, double meanMicros, double p50Micros, double p95Micros,
                         double p99Micros, double maxMicros, Dur service, double eventsPerSecond,
                         long heapUsedBytes) {

        public String summary() {
            StringBuilder out = new StringBuilder();
            double measuredSeconds = Math.max(0.001, elapsedMillis / 1000.0);
            out.append(String.format(Locale.ROOT,
                    "Soak report: %d s requested, %.1f s measured, %.0f events/s target%n",
                    requestedSeconds, measuredSeconds, targetRate));
            out.append(String.format(Locale.ROOT,
                    "events: %,d offered, %,d processed, %,d dropped, %,d alerts detected, %,d delivered%n",
                    offered, processed, dropped, detected, alerts));
            out.append(String.format(Locale.ROOT, "store: %,d rows written during the run%n", storeRows));
            out.append(String.format(Locale.ROOT,
                    "queue: depth max %,d, mean %.2f%n", maxQueueDepth, meanQueueDepth));
            out.append(String.format(Locale.ROOT,
                    "latency: %,d samples, mean %.2f us, p50 %.2f us, p95 %.2f us, p99 %.2f us, max %.2f us%n",
                    samples, meanMicros, p50Micros, p95Micros, p99Micros, maxMicros));
            out.append(String.format(Locale.ROOT, "service: %s%n", service.line()));
            out.append(String.format(Locale.ROOT,
                    "throughput: %.0f events/s, heap used at end %,d MB",
                    eventsPerSecond, heapUsedBytes / (1024L * 1024L)));
            return out.toString();
        }
    }

    private static final Instant BASE = Instant.parse("2026-01-01T00:00:00Z");

    private Soak() {
    }

    public static Report run(IncidentResponseFacade facade, int seconds) {
        ConfigManager config = ConfigManager.getInstance();
        double rate = Math.max(1.0, config.getDouble("bench.soak.eventsPerSecond", 2000.0));
        int maxDepth = Math.max(1, config.getInt("bench.soak.maxQueueDepth", 5000));
        return run(facade, seconds, rate, maxDepth);
    }

    public static Report run(IncidentResponseFacade facade, int seconds, double eventsPerSecond,
                             int maxQueueDepth) {
        return run(facade.getDetectionEngine(), () -> writtenRows(facade), seconds, eventsPerSecond, maxQueueDepth);
    }

    static Report run(DetectionEngine engine, LongSupplier writtenRows, int seconds, double eventsPerSecond,
                      int maxQueueDepth) {
        int requested = Math.max(1, seconds);
        double rate = Math.max(1.0, eventsPerSecond);
        int maxDepth = Math.max(1, maxQueueDepth);
        int progressSeconds = Math.max(0, ConfigManager.getInstance().getInt("bench.soak.progressSeconds", 60));

        BlockingQueue<NetworkEvent> queue = engine.getQueue();
        long startedAt = System.nanoTime();
        long detectedBefore = engine.getDetectedAlerts();
        long droppedBefore = engine.getDroppedEvents();
        long processedBefore = engine.getProcessedEvents();
        long writtenBefore = writtenRows.getAsLong();

        AtomicLong delivered = new AtomicLong();
        AlertListener counter = alert -> delivered.incrementAndGet();
        engine.getAlertBus().subscribe(counter);

        ConcurrentHashMap<Long, Long> queuedAt = new ConcurrentHashMap<>();
        AtomicLong offered = new AtomicLong();
        long[] samples = new long[1 << 15];
        long[] services = new long[1 << 15];
        AtomicLong dequeued = new AtomicLong();
        int[] depthPeak = {0};
        long[] depthSum = {0L};
        long[] depthCount = {0L};
        boolean[] producing = {true};

        Thread producer = new Thread(() -> {
            long deadline = System.nanoTime() + requested * 1_000_000_000L;
            long sequence = 0L;
            try {
                while (System.nanoTime() < deadline) {
                    long elapsed = System.nanoTime() - startedAt;
                    long due = (long) (elapsed / 1_000_000_000.0 * rate);
                    while (sequence < due && System.nanoTime() < deadline) {
                        while (queue.size() >= maxDepth && System.nanoTime() < deadline) {
                            LockSupport.parkNanos(1_000_000L);
                        }
                        NetworkEvent event = event(sequence);
                        queuedAt.put(event.id(), System.nanoTime());
                        if (queue.offer(event)) {
                            offered.incrementAndGet();
                            sequence++;
                        } else {
                            queuedAt.remove(event.id());
                            LockSupport.parkNanos(100_000L);
                        }
                    }
                    LockSupport.parkNanos(500_000L);
                }
            } finally {
                producing[0] = false;
            }
        }, "Soak-producer");
        producer.setDaemon(true);
        producer.start();

        int sampleCount = 0;
        long lastProgress = System.nanoTime();
        try {
            while (producing[0] || !queue.isEmpty()) {
                NetworkEvent event = queue.poll(50, TimeUnit.MILLISECONDS);
                if (event == null) {
                    continue;
                }
                Long stamped = queuedAt.remove(event.id());
                long before = System.nanoTime();
                engine.processNow(event);
                long finished = System.nanoTime();
                dequeued.incrementAndGet();
                if (sampleCount == samples.length) {
                    samples = Arrays.copyOf(samples, samples.length * 2);
                    services = Arrays.copyOf(services, services.length * 2);
                }
                services[sampleCount] = finished - before;
                if (stamped != null) {
                    samples[sampleCount++] = finished - stamped;
                }
                int depth = queue.size();
                depthPeak[0] = Math.max(depthPeak[0], depth);
                depthSum[0] += depth;
                depthCount[0]++;
                long now = System.nanoTime();
                if (progressSeconds > 0 && now - lastProgress >= progressSeconds * 1_000_000_000L) {
                    lastProgress = now;
                    System.out.printf(Locale.ROOT,
                            "soak %4.0f s: %,d taken, queue max %,d, %,d alerts%n",
                            (now - startedAt) / 1_000_000_000.0, dequeued.get(), depthPeak[0], delivered.get());
                }
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } finally {
            producing[0] = false;
            try {
                producer.join(2000L);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
            engine.getAlertBus().unsubscribe(counter);
        }

        long elapsedMillis = Math.max(1L, (System.nanoTime() - startedAt) / 1_000_000L);
        long[] sorted = Arrays.copyOf(samples, sampleCount);
        Arrays.sort(sorted);
        long[] sortedServices = Arrays.copyOf(services, sampleCount);
        Arrays.sort(sortedServices);
        long totalNanos = 0L;
        for (int i = 0; i < sampleCount; i++) {
            totalNanos += sorted[i];
        }
        double mean = sampleCount == 0 ? 0.0 : totalNanos / 1000.0 / sampleCount;
        double throughput = dequeued.get() * 1000.0 / elapsedMillis;
        long heapUsed = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        return new Report(requested, elapsedMillis, rate, offered.get(),
                engine.getProcessedEvents() - processedBefore,
                engine.getDroppedEvents() - droppedBefore, engine.getDetectedAlerts() - detectedBefore,
                delivered.get(), writtenRows.getAsLong() - writtenBefore, depthPeak[0],
                depthCount[0] == 0 ? 0.0 : depthSum[0] / (double) depthCount[0],
                sampleCount, mean, percentile(sorted, 0.50), percentile(sorted, 0.95),
                percentile(sorted, 0.99), sorted.length == 0 ? 0.0 : sorted[sorted.length - 1] / 1000.0,
                Dur.from(sortedServices), throughput, heapUsed);
    }

    private static long writtenRows(IncidentResponseFacade facade) {
        PersistenceStatus status = facade.getPersistenceService().status();
        return status == null ? 0L : status.writtenRows();
    }

    private static double percentile(long[] sorted, double fraction) {
        if (sorted.length == 0) {
            return 0.0;
        }
        int rank = (int) Math.ceil(fraction * sorted.length);
        int index = Math.min(sorted.length - 1, Math.max(0, rank - 1));
        return sorted[index] / 1000.0;
    }

    private static NetworkEvent event(long sequence) {
        long block = sequence / 1000L;
        long offset = sequence % 1000L;
        String source;
        String target;
        int port;
        if (offset < 200L) {
            source = "10.9." + (block % 50) + ".5";
            target = "10.1.0.1";
            port = 1 + (int) offset;
        } else {
            source = "10.0." + ((sequence / 200) % 20) + "." + (sequence % 200);
            target = "10.1.0." + (1 + (sequence % 8));
            port = 1024 + (int) (sequence % 40);
        }
        EventType type = EventType.values()[(int) (sequence % EventType.values().length)];
        return new NetworkEvent(sequence + 1L, BASE.plusMillis(sequence), source, target, port,
                200 + (int) (sequence % 900), type, sequence % 11 != 0, "NORMAL", true);
    }
}
