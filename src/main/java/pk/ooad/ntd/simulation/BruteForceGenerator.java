package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

public class BruteForceGenerator extends AttackGenerator {

    @Override
    public List<NetworkEvent> generate(String src, String dst, Instant now, Random rnd) {
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(rnd, "rnd must not be null");

        List<NetworkEvent> events = new ArrayList<>();
        int attempts = 15;
        int port = 22;

        for (long id = 1; id <= attempts; id++) {
            long bytes = 120L + rnd.nextInt(60);
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

