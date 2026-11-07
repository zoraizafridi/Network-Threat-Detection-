package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import pk.ooad.ntd.util.ConfigManager;

public class PortScanGenerator extends AttackGenerator {
    private final int[] ports = configuredPorts();

    private static int[] configuredPorts() {
        String raw = ConfigManager.getInstance().getString("sim.portscan.ports",
                "21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,8080");
        List<Integer> parsed = new ArrayList<>();
        for (String part : raw.split(",")) {
            if (part.isBlank()) {
                continue;
            }
            try {
                parsed.add(Integer.parseInt(part.trim()));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid sim.portscan.ports configuration", e);
            }
        }
        int[] result = new int[parsed.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = parsed.get(i);
        }
        return result;
    }

    @Override
    public List<NetworkEvent> generate(String src, String dst, Instant now, Random rnd) {
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(rnd, "rnd must not be null");

        List<NetworkEvent> events = new ArrayList<>();
        long id = 1L;

        for (int port : ports) {
            long bytes = 40L + rnd.nextInt(25);
            events.add(new NetworkEvent(
                id++,
                now.plusMillis((id - 1) * 10),
                src != null ? src : "",
                dst != null ? dst : "",
                port,
                bytes,
                EventType.CONNECT,
                false,
                "PORT_SCAN_SYN"
            ));
        }

        return events;
    }
}

