package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import pk.ooad.ntd.util.ConfigManager;

public class DataTransferGenerator extends AttackGenerator {
    private final int count = ConfigManager.getInstance().getInt("sim.exfil.chunks", 5);
    private final int port = ConfigManager.getInstance().getInt("sim.exfil.port", 443);
    private final int baseBytes = ConfigManager.getInstance().getInt("sim.exfil.baseBytes", 1_000_000);
    private final int jitterBytes = ConfigManager.getInstance().getInt("sim.exfil.jitterBytes", 500_000);

    @Override
    public List<NetworkEvent> generate(String src, String dst, Instant now, Random rnd) {
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(rnd, "rnd must not be null");

        List<NetworkEvent> events = new ArrayList<>();

        for (long id = 1; id <= count; id++) {
            long bytes = baseBytes + rnd.nextInt(Math.max(1, jitterBytes));
            events.add(new NetworkEvent(
                id,
                now.plusSeconds(id - 1),
                src != null ? src : "",
                dst != null ? dst : "",
                port,
                bytes,
                EventType.DATA_TRANSFER,
                true,
                "DATA_EXFILTRATION_CHUNK"
            ));
        }

        return events;
    }
}
