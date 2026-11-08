package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.EventType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.intel.IntelEntry;
import pk.ooad.ntd.intel.ThreatIntel;
import pk.ooad.ntd.util.ConfigManager;

import java.util.Optional;

/**
 * Raises an alert when an event's source is listed in the threat feed.
 *
 * <p>The feed decides <em>whether</em> to alert; the event decides which
 * {@link AttackType} bucket it lands in, because the existing four buckets are
 * the ones the UI and the incident correlation understand. The precise reason
 * lives in the description, which names the matched entry and its label.</p>
 */
public class ThreatIntelDetector extends Detector {

    private final ThreatIntel intel;
    private final boolean enabled;

    public ThreatIntelDetector() {
        this("ThreatIntelDetector", ThreatIntel.fromConfig(),
                Boolean.parseBoolean(ConfigManager.getInstance().getString("intel.enabled", "false")));
    }

    public ThreatIntelDetector(String name, ThreatIntel intel, boolean enabled) {
        super(name != null ? name : "ThreatIntelDetector");
        this.intel = intel == null ? ThreatIntel.parse("", "none", Severity.HIGH) : intel;
        this.enabled = enabled;
    }

    @Override
    public Optional<Alert> analyze(NetworkEvent e) {
        if (!enabled || e == null || e.sourceIp() == null) {
            return Optional.empty();
        }
        Optional<IntelEntry> hit = intel.match(e.sourceIp());
        if (hit.isEmpty()) {
            return Optional.empty();
        }
        IntelEntry entry = hit.get();
        String description = "Source " + e.sourceIp() + " matches threat feed entry "
                + entry.cidr() + " (" + entry.label() + ")";
        return Optional.of(alertFactory.create(
                entry.severity(),
                attackTypeFor(e.type()),
                e.sourceIp(),
                e.destIp(),
                getName(),
                description,
                e.timestamp()));
    }

    @Override
    public void reset() {
        // Stateless: the feed is read once at construction.
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
