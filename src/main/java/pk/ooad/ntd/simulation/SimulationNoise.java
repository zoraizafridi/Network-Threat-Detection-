package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.util.ConfigManager;

import java.util.Objects;
import java.util.Random;

public final class SimulationNoise {

    private final boolean enabled;
    private final double benignSpikeChance;
    private final long benignSpikeBytes;
    private final double retryChance;
    private final double portSpreadChance;
    private final double attackVariantChance;
    private final int scanPortOffset;
    private final int brutePort;
    private final int floodPort;

    public SimulationNoise(boolean enabled, double benignSpikeChance, long benignSpikeBytes, double retryChance,
                           double portSpreadChance, double attackVariantChance, int scanPortOffset,
                           int brutePort, int floodPort) {
        this.enabled = enabled;
        this.benignSpikeChance = chance(benignSpikeChance);
        this.benignSpikeBytes = Math.max(0L, benignSpikeBytes);
        this.retryChance = chance(retryChance);
        this.portSpreadChance = chance(portSpreadChance);
        this.attackVariantChance = chance(attackVariantChance);
        this.scanPortOffset = Math.max(1, scanPortOffset);
        this.brutePort = port(brutePort, 3389);
        this.floodPort = port(floodPort, 443);
    }

    public static SimulationNoise from(ConfigManager config) {
        Objects.requireNonNull(config, "config must not be null");
        return new SimulationNoise(
                Boolean.parseBoolean(config.getString("sim.noise.enabled", "false")),
                config.getDouble("sim.noise.benignSpikeChance", 0.03),
                config.getInt("sim.noise.benignSpikeBytes", 2_000_000),
                config.getDouble("sim.noise.retryChance", 0.05),
                config.getDouble("sim.noise.portSpreadChance", 0.10),
                config.getDouble("sim.noise.attackVariantChance", 0.25),
                config.getInt("sim.noise.scanPortOffset", 8000),
                config.getInt("sim.noise.variantBrutePort", 3389),
                config.getInt("sim.noise.variantFloodPort", 443));
    }

    public static SimulationNoise off() {
        return new SimulationNoise(false, 0.0, 0L, 0.0, 0.0, 0.0, 8000, 3389, 443);
    }

    public boolean enabled() {
        return enabled;
    }

    public double attackVariantChance() {
        return attackVariantChance;
    }

    public NetworkEvent decorate(NetworkEvent event, Random random) {
        if (!enabled || event == null || random == null) {
            return event;
        }
        double roll = random.nextDouble();
        if (roll < benignSpikeChance && benignSpikeBytes > 0) {
            long bytes = benignSpikeBytes + Math.round(random.nextDouble() * benignSpikeBytes * 0.5);
            return copy(event, 443, bytes, EventType.DATA_TRANSFER, true, "NORMAL_BACKUP");
        }
        if (roll < benignSpikeChance + retryChance) {
            return copy(event, event.port(), event.bytes(), event.type(), false, "NORMAL_RETRY");
        }
        if (roll < benignSpikeChance + retryChance + portSpreadChance) {
            int port = 1024 + random.nextInt(64_000);
            return copy(event, port, event.bytes(), event.type(), event.success(), "NORMAL_UNCOMMON_PORT");
        }
        return event;
    }

    public boolean variant(Random random) {
        return enabled && random != null && attackVariantChance > 0 && random.nextDouble() < attackVariantChance;
    }

    public NetworkEvent shape(NetworkEvent event, AttackType type, boolean variant, Random random) {
        if (!variant || event == null || type == null) {
            return event;
        }
        switch (type) {
            case PORT_SCAN:
                return copy(event, event.port() + scanPortOffset, event.bytes(), event.type(),
                        event.success(), "PORT_SCAN_SYN_VARIANT");
            case BRUTE_FORCE:
                return copy(event, brutePort, Math.round(event.bytes() * 1.4),
                        EventType.LOGIN_ATTEMPT, false, "AUTH_FAILED user=administrator");
            case DOS_FLOOD:
                return copy(event, floodPort, Math.round(event.bytes() * 1.5),
                        EventType.REQUEST, event.success(), "GET / HTTP/1.1");
            case DATA_TRANSFER:
                return copy(event, event.port(), Math.round(event.bytes() * 1.5),
                        EventType.DATA_TRANSFER, true, "DATA_UPLOAD chunk");
            default:
                return event;
        }
    }

    private static NetworkEvent copy(NetworkEvent event, int port, long bytes, EventType type,
                                     boolean success, String payload) {
        return new NetworkEvent(event.id(), event.timestamp(), event.sourceIp(), event.destIp(), port,
                Math.max(1L, bytes), type, success, payload);
    }

    private static double chance(double value) {
        return Math.max(0.0, Math.min(1.0, value));
    }

    private static int port(int value, int fallback) {
        return value > 0 && value <= 65_535 ? value : fallback;
    }
}
