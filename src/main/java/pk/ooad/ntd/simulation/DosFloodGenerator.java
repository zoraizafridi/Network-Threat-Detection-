package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

public class DosFloodGenerator extends AttackGenerator {

    @Override
    public List<NetworkEvent> generate(String src, String dst, Instant now, Random rnd) {
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(rnd, "rnd must not be null");

        List<NetworkEvent> events = new ArrayList<>();
        int count = 40;
        int port = 80;

        for (long id = 1; id <= count; id++) {
            long bytes = 400L + rnd.nextInt(200);
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

