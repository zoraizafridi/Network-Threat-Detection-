package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

public class TrafficSimulator {
    private final Clock clock;
    private final Random random;
    private final BlockingQueue<NetworkEvent> queue;
    private final AtomicBoolean running;
    private volatile boolean autoMode;

    private final Network network;
    private HostProfile hostProfile;
    private volatile SimulationNoise noise;
    private final Map<AttackType, AttackGenerator> attackGenerators;
    private final List<AttackRecord> groundTruth;

    private long nextEventId = 1L;
    private Thread workerThread;

    public TrafficSimulator(Network network, Clock clock, Random random, BlockingQueue<NetworkEvent> queue) {
        this.network = network;
        this.clock = clock != null ? clock : Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        this.random = random != null ? random : new Random(0L);
        this.queue = queue != null ? queue : new LinkedBlockingQueue<>();
        this.running = new AtomicBoolean(false);
        this.autoMode = false;

        this.hostProfile = new HostProfile();
        this.noise = SimulationNoise.from(ConfigManager.getInstance());
        this.groundTruth = new CopyOnWriteArrayList<>();
        this.attackGenerators = new EnumMap<>(AttackType.class);

        this.attackGenerators.put(AttackType.PORT_SCAN, new PortScanGenerator());
        this.attackGenerators.put(AttackType.BRUTE_FORCE, new BruteForceGenerator());
        this.attackGenerators.put(AttackType.DOS_FLOOD, new DosFloodGenerator());
        this.attackGenerators.put(AttackType.DATA_TRANSFER, new DataTransferGenerator());
    }

    public TrafficSimulator(Network network, Clock clock, Random random) {
        this(network, clock, random, new LinkedBlockingQueue<>());
    }

    public TrafficSimulator(Network network, Clock clock, long seed) {
        this(network, clock, new Random(seed), new LinkedBlockingQueue<>());
    }

    public TrafficSimulator(Network network, Random random) {
        this(network, Clock.systemUTC(), random, new LinkedBlockingQueue<>());
    }

    public TrafficSimulator(Network network, long seed) {
        this(network, Clock.systemUTC(), new Random(seed), new LinkedBlockingQueue<>());
    }

    public TrafficSimulator(long seed) {
        this(null, Clock.systemUTC(), new Random(seed), new LinkedBlockingQueue<>());
    }

    public TrafficSimulator() {
        this(null, Clock.systemUTC(), new Random(0L), new LinkedBlockingQueue<>());
    }

    public synchronized void start() {
        if (running.compareAndSet(false, true)) {
            startWorkerIfNeeded();
        }
    }

    public synchronized void stop() {
        running.set(false);
        if (workerThread != null) {
            workerThread.interrupt();
            workerThread = null;
        }
    }

    public synchronized void reset() {
        stop();
        queue.clear();
        groundTruth.clear();
        nextEventId = 1L;
    }

    public synchronized void setAutoMode(boolean on) {
        this.autoMode = on;
        if (running.get() && autoMode) {
            startWorkerIfNeeded();
        }
    }

    public void injectAttack(AttackType type, String srcIp, String dstIp) {
        Objects.requireNonNull(type, "AttackType must not be null");
        AttackGenerator generator = attackGenerators.get(type);
        if (generator == null) {
            throw new IllegalArgumentException("No attack generator registered for: " + type);
        }

        Instant now = clock.instant();
        List<NetworkEvent> rawEvents = generator.generate(srcIp, dstIp, now, random);
        boolean variant = noise.variant(random);

        synchronized (this) {
            for (NetworkEvent raw : rawEvents) {
                NetworkEvent shaped = noise.shape(raw, type, variant, random);
                NetworkEvent event = new NetworkEvent(
                    nextEventId++,
                    shaped.timestamp(),
                    shaped.sourceIp(),
                    shaped.destIp(),
                    shaped.port(),
                    shaped.bytes(),
                    shaped.type(),
                    shaped.success(),
                    shaped.payload(),
                    true
                );
                queue.offer(event);
            }
            groundTruth.add(new AttackRecord(type, srcIp, dstIp, now));
        }
    }

    public synchronized NetworkEvent generateNormalEvent() {
        long id = nextEventId++;
        Instant timestamp = clock.instant();

        String sourceIp;
        String destIp;
        if (network != null && network.getAssets().size() >= 2) {
            List<NetworkAsset> assets = new ArrayList<>(network.getAssets());
            int srcIdx = random.nextInt(assets.size());
            int dstIdx = random.nextInt(assets.size());
            while (dstIdx == srcIdx && assets.size() > 1) {
                dstIdx = random.nextInt(assets.size());
            }
            sourceIp = assets.get(srcIdx).getIp();
            destIp = assets.get(dstIdx).getIp();
        } else {
            sourceIp = "10.0.0." + (1 + random.nextInt(20));
            destIp = "10.0.0." + (1 + random.nextInt(20));
        }

        int port;
        List<Integer> ports = hostProfile != null ? hostProfile.getCommonPorts() : null;
        if (ports != null && !ports.isEmpty()) {
            port = ports.get(random.nextInt(ports.size()));
        } else {
            port = 80;
        }

        double mean = hostProfile != null ? hostProfile.getMeanBytes() : 512.0;
        double std = hostProfile != null ? hostProfile.getStdBytes() : 64.0;
        double sampledBytes = mean + (random.nextGaussian() * std);
        long bytes = Math.max(40L, Math.round(sampledBytes));

        EventType[] normalTypes = {EventType.REQUEST, EventType.CONNECT, EventType.DATA_TRANSFER};
        EventType type = normalTypes[random.nextInt(normalTypes.length)];
        boolean success = random.nextDouble() < 0.95;
        String payload = "NORMAL_PAYLOAD";

        return noise.decorate(new NetworkEvent(id, timestamp, sourceIp, destIp, port, bytes, type, success, payload), random);
    }

    public BlockingQueue<NetworkEvent> getEventQueue() {
        return queue;
    }

    public boolean isRunning() {
        return running.get();
    }

    public boolean isAutoMode() {
        return autoMode;
    }

    public List<AttackRecord> getGroundTruth() {
        return Collections.unmodifiableList(groundTruth);
    }

    public Network getNetwork() {
        return network;
    }

    public HostProfile getHostProfile() {
        return hostProfile;
    }

    public void setHostProfile(HostProfile hostProfile) {
        this.hostProfile = hostProfile != null ? hostProfile : new HostProfile();
    }

    public SimulationNoise getNoise() {
        return noise;
    }

    public void setNoise(SimulationNoise noise) {
        this.noise = noise != null ? noise : SimulationNoise.off();
    }

    private synchronized void startWorkerIfNeeded() {
        if (running.get() && autoMode && (workerThread == null || !workerThread.isAlive())) {
            workerThread = new Thread(() -> {
                while (running.get()) {
                    if (autoMode) {
                        NetworkEvent event = generateNormalEvent();
                        queue.offer(event);
                    }
                    try {
                        double rate = (hostProfile != null && hostProfile.getEventsPerSecond() > 0)
                                ? hostProfile.getEventsPerSecond()
                                : 5.0;
                        long sleepMs = Math.max(5L, (long) (1000.0 / rate));
                        Thread.sleep(sleepMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }, "TrafficSimulator-Thread");
            workerThread.setDaemon(true);
            workerThread.start();
        }
    }
}
