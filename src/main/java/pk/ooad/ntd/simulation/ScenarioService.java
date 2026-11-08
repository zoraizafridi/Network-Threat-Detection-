package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.function.Consumer;

public final class ScenarioService {

    private static final int BEACON_COUNT = 12;
    private static final long BEACON_INTERVAL_SECONDS = 30;
    private static final int LATERAL_HOSTS = 6;
    private static final String DEFAULT_SOURCE = "10.0.2.12";
    private static final String DEFAULT_TARGET = "10.0.1.20";
    private static final String LISTED_SOURCE = "198.51.100.7";
    private static final String LISTED_DOMAIN = "update.example.org";
    private static final String LISTED_DIGEST =
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    public record Preset(String name, String title, String summary) {
    }

    public record Result(String preset, String title, String source, String target, int events,
                         List<AttackType> attackTypes) {
    }

    private static final List<Preset> PRESETS = List.of(
            new Preset("port-scan", "Port scan", "One source touches many ports on one host"),
            new Preset("brute-force", "Brute force", "Repeated failed logins against one account"),
            new Preset("flood", "Denial of service", "A burst of requests that saturates a host"),
            new Preset("data-transfer", "Bulk transfer", "Large outbound transfers to one destination"),
            new Preset("beaconing", "Beaconing", "A steady callback every thirty seconds with no jitter"),
            new Preset("lateral-movement", "Lateral movement", "Failed logins against six hosts on management ports"),
            new Preset("intel-contact", "Indicator contact", "A listed address fetches a listed domain and digest"));

    public List<Preset> presets() {
        return PRESETS;
    }

    public Result run(String preset, String source, String target, long seed, Consumer<NetworkEvent> sink) {
        String name = preset == null ? "" : preset.trim().toLowerCase(Locale.ROOT);
        String src = source == null || source.isBlank() ? DEFAULT_SOURCE : source.trim();
        String dst = target == null || target.isBlank() ? DEFAULT_TARGET : target.trim();
        Random rnd = new Random(seed);
        Instant now = Instant.now();
        List<NetworkEvent> events = new ArrayList<>();
        switch (name) {
            case "port-scan" -> events.addAll(new PortScanGenerator().generate(src, dst, now, rnd));
            case "brute-force" -> events.addAll(new BruteForceGenerator().generate(src, dst, now, rnd));
            case "flood" -> events.addAll(new DosFloodGenerator().generate(src, dst, now, rnd));
            case "data-transfer" -> events.addAll(new DataTransferGenerator().generate(src, dst, now, rnd));
            case "beaconing" -> events.addAll(beacons(src, dst, now, rnd));
            case "lateral-movement" -> events.addAll(lateral(src, dst, now, rnd));
            case "intel-contact" -> events.addAll(indicatorContact(src, dst, now));
            default -> throw new IllegalArgumentException("unknown scenario: " + preset);
        }
        List<AttackType> types = new ArrayList<>();
        for (NetworkEvent event : events) {
            if (sink != null) {
                sink.accept(event);
            }
            AttackType type = typeOf(event);
            if (!types.contains(type)) {
                types.add(type);
            }
        }
        return new Result(name, titleOf(name), src, dst, events.size(), List.copyOf(types));
    }

    private List<NetworkEvent> beacons(String src, String dst, Instant now, Random rnd) {
        List<NetworkEvent> events = new ArrayList<>();
        for (int i = 0; i < BEACON_COUNT; i++) {
            Instant at = now.plusSeconds(i * BEACON_INTERVAL_SECONDS).plusMillis(rnd.nextInt(200));
            events.add(new NetworkEvent(6_000_000L + i, at, src, dst, 443, 512L,
                    EventType.CONNECT, true, "BEACON heartbeat"));
        }
        return events;
    }

    private List<NetworkEvent> lateral(String src, String dst, Instant now, Random rnd) {
        List<NetworkEvent> events = new ArrayList<>();
        String prefix = dst.contains(".") ? dst.substring(0, dst.lastIndexOf('.') + 1) : "10.0.1.";
        int last = 20;
        try {
            last = Integer.parseInt(dst.substring(dst.lastIndexOf('.') + 1));
        } catch (RuntimeException ex) {
            last = 20;
        }
        int[] ports = {22, 445, 3389, 22, 445, 3389};
        for (int i = 0; i < LATERAL_HOSTS; i++) {
            Instant at = now.plusSeconds(i * 4L).plusMillis(rnd.nextInt(400));
            events.add(new NetworkEvent(6_100_000L + i, at, src, prefix + (last + i), ports[i],
                    420L, EventType.LOGIN_ATTEMPT, false, "AUTH_FAILED admin login"));
        }
        return events;
    }

    private List<NetworkEvent> indicatorContact(String src, String dst, Instant now) {
        String listed = LISTED_SOURCE.equals(src) ? src : LISTED_SOURCE;
        List<NetworkEvent> events = new ArrayList<>();
        events.add(new NetworkEvent(6_200_000L, now, listed, dst, 80, 640L,
                EventType.REQUEST, true, "GET /index.html"));
        events.add(new NetworkEvent(6_200_001L, now.plusSeconds(1), src, dst, 443, 2_048L,
                EventType.REQUEST, true, "GET https://" + LISTED_DOMAIN + "/loader.bin"));
        events.add(new NetworkEvent(6_200_002L, now.plusSeconds(2), src, dst, 443, 4_096L,
                EventType.DATA_TRANSFER, true, "POST sha256=" + LISTED_DIGEST));
        return events;
    }

    private static AttackType typeOf(NetworkEvent event) {
        if (event.type() == EventType.DATA_TRANSFER) {
            return AttackType.DATA_TRANSFER;
        }
        if (event.type() == EventType.LOGIN_ATTEMPT) {
            return AttackType.BRUTE_FORCE;
        }
        return AttackType.PORT_SCAN;
    }

    private static String titleOf(String name) {
        for (Preset preset : PRESETS) {
            if (preset.name().equals(name)) {
                return preset.title();
            }
        }
        return name;
    }
}
