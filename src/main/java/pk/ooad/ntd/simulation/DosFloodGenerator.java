package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import pk.ooad.ntd.util.ConfigManager;

public class DosFloodGenerator extends AttackGenerator {
    private final int count = ConfigManager.getInstance().getInt("sim.flood.count", 40);
    private final int port = ConfigManager.getInstance().getInt("sim.flood.port", 80);
    private final int baseBytes = ConfigManager.getInstance().getInt("sim.flood.baseBytes", 400);

    @Override
    public List<NetworkEvent> generate(String src, String dst, Instant now, Random rnd) {
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(rnd, "rnd must not be null");

        List<NetworkEvent> events = new ArrayList<>();

        for (long id = 1; id <= count; id++) {
            long bytes = baseBytes + rnd.nextInt(Math.max(1, baseBytes / 2));
            events.add(new NetworkEvent(
                id,
                now.plusMillis((id - 1) * 5),
                src != null ? src : "",
                dst != null ? dst : "",
                port,
                bytes,
                EventType.REQUEST,
                rnd.nextBoolean(),
                "DOS_FLOOD_PAYLOAD"
            ));
        }

        return events;
    }
}
