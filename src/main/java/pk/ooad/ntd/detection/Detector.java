package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.NetworkEvent;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public abstract class Detector {
    protected String name;
    protected final AlertFactory alertFactory = new AlertFactory();

    protected Detector(String name) {
        this.name = Objects.requireNonNull(name, "name must not be null");
    }

    public String getName() {
        return name;
    }

    public abstract Optional<Alert> analyze(NetworkEvent e);

    public abstract void reset();

    protected static boolean listed(List<String> entries, String ip) {
        if (entries == null || entries.isEmpty() || ip == null || ip.isBlank()) {
            return false;
        }
        for (String entry : entries) {
            if (matches(entry, ip)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matches(String entry, String ip) {
        if (entry == null || entry.isBlank()) {
            return false;
        }
        String rule = entry.trim();
        int slash = rule.indexOf('/');
        if (slash < 0) {
            return rule.equals(ip.trim());
        }
        int bits;
        try {
            bits = Integer.parseInt(rule.substring(slash + 1));
        } catch (NumberFormatException ex) {
            return false;
        }
        long network = ipv4(rule.substring(0, slash));
        long address = ipv4(ip.trim());
        if (network < 0 || address < 0 || bits < 0 || bits > 32) {
            return false;
        }
        long mask = bits == 0 ? 0L : (0xFFFF_FFFFL << (32 - bits)) & 0xFFFF_FFFFL;
        return (network & mask) == (address & mask);
    }

    private static long ipv4(String raw) {
        String[] parts = raw.split("\\.");
        if (parts.length != 4) {
            return -1L;
        }
        long value = 0L;
        for (String part : parts) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException ex) {
                return -1L;
            }
            if (octet < 0 || octet > 255) {
                return -1L;
            }
            value = (value << 8) | octet;
        }
        return value;
    }
}
