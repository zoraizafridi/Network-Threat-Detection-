package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

public class DataTransferGenerator extends AttackGenerator {

    @Override
    public List<NetworkEvent> generate(String src, String dst, Instant now, Random rnd) {
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(rnd, "rnd must not be null");

        List<NetworkEvent> events = new ArrayList<>();
        int count = 5;
        int port = 443;

        for (long id = 1; id <= count; id++) {
            long bytes = 1_000_000L + rnd.nextInt(500_000);
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

