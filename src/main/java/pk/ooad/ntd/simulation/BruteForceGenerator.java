package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import pk.ooad.ntd.util.ConfigManager;

public class BruteForceGenerator extends AttackGenerator {
    private final int attempts = ConfigManager.getInstance().getInt("sim.brute.attempts", 15);
    private final int port = ConfigManager.getInstance().getInt("sim.brute.port", 22);
    private final int baseBytes = ConfigManager.getInstance().getInt("sim.brute.baseBytes", 120);

    @Override
    public List<NetworkEvent> generate(String src, String dst, Instant now, Random rnd) {
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(rnd, "rnd must not be null");

        List<NetworkEvent> events = new ArrayList<>();

        for (long id = 1; id <= attempts; id++) {
            long bytes = baseBytes + rnd.nextInt(Math.max(1, baseBytes / 2));
            events.add(new NetworkEvent(
                id,
                now.plusMillis((id - 1) * 50),
                src != null ? src : "",
                dst != null ? dst : "",
                port,
                bytes,
                EventType.LOGIN_ATTEMPT,
                false,
                "AUTH_FAILED user=root"
            ));
        }

        return events;
    }
}

