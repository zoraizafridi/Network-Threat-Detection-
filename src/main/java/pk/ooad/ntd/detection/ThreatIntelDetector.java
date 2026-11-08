package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.intel.IntelEntry;
import pk.ooad.ntd.intel.ThreatIntel;
import pk.ooad.ntd.util.ConfigManager;

import java.util.Locale;
import java.util.Optional;

public class ThreatIntelDetector extends Detector {

    private volatile ThreatIntel intel;
    private final boolean enabled;

    public ThreatIntelDetector() {
        this("ThreatIntelDetector", ThreatIntel.fromConfig(),
                Boolean.parseBoolean(ConfigManager.getInstance().getString("intel.enabled", "false")));
    }

    public ThreatIntelDetector(String name, ThreatIntel intel, boolean enabled) {
        super(name != null ? name : "ThreatIntelDetector");
        this.intel = intel == null ? ThreatIntel.empty("none") : intel;
        this.enabled = enabled;
    }

    @Override
    public Optional<Alert> analyze(NetworkEvent e) {
        if (!enabled || e == null) {
            return Optional.empty();
        }
        ThreatIntel feed = intel;
        IntelEntry entry;
        String where;
        Optional<IntelEntry> byAddress = feed.match(e.sourceIp());
        if (byAddress.isPresent()) {
            entry = byAddress.get();
            where = "Source " + e.sourceIp() + " matches";
        } else {
            Optional<IntelEntry> byPayload = feed.matchPayload(e.payload());
            if (byPayload.isEmpty()) {
                return Optional.empty();
            }
            entry = byPayload.get();
            where = "Payload from " + e.sourceIp() + " carries";
        }
        String description = where + " threat feed " + entry.type().name().toLowerCase(Locale.ROOT)
                + " indicator " + entry.value() + " (" + entry.label() + ", category "
                + entry.category() + ", confidence " + entry.confidence() + ")";
        return Optional.of(alertFactory.create(
                entry.severity(),
                attackTypeFor(e.type()),
                e.sourceIp(),
                e.destIp(),
                getName(),
                description,
                e.timestamp()));
    }

    public void reload(ThreatIntel feed) {
        this.intel = feed == null ? ThreatIntel.empty("none") : feed;
    }

    public ThreatIntel feed() {
        return intel;
    }

    @Override
    public void reset() {
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int feedSize() {
        return intel.size();
    }

    static AttackType attackTypeFor(EventType type) {
        if (type == null) {
            return AttackType.PORT_SCAN;
        }
        return switch (type) {
            case LOGIN_ATTEMPT -> AttackType.BRUTE_FORCE;
            case DATA_TRANSFER -> AttackType.DATA_TRANSFER;
            case CONNECT, REQUEST -> AttackType.PORT_SCAN;
        };
    }
}
