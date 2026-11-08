package pk.ooad.ntd.intel;

import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * A small, offline threat feed.
 *
 * <p>Lines are {@code network label [severity]}, where network is an IPv4
 * address or CIDR block. {@code #} starts a comment. Example:</p>
 *
 * <pre>
 * 203.0.113.0/24   scanner-net   HIGH
 * 198.51.100.7     known-c2      CRITICAL
 * </pre>
 *
 * <p>Only IPv4 is matched. IPv6 entries are counted and skipped rather than
 * half-parsed, because a silent mismatch would look like "no match" in a report.
 * The feed is loaded once and held in a sorted array so a lookup is a scan over
 * a small list, which is plenty for a teaching scale feed and avoids a
 * dependency.</p>
 */
public final class ThreatIntel {

    private final List<IntelEntry> entries;
    private final long[] networkStarts;
    private final int[] prefixes;
    private final long skipped;

    private ThreatIntel(List<IntelEntry> entries, long skipped) {
        this.entries = List.copyOf(entries);
        this.skipped = skipped;
        this.networkStarts = new long[this.entries.size()];
        this.prefixes = new int[this.entries.size()];
        for (int i = 0; i < this.entries.size(); i++) {
            long[] parsed = parseCidr(this.entries.get(i).cidr());
            this.networkStarts[i] = parsed[0];
            this.prefixes[i] = (int) parsed[1];
        }
    }

    public static ThreatIntel fromConfig() {
        ConfigManager config = ConfigManager.getInstance();
        String feed = config.getString("intel.feed", "threat-intel.txt");
        Severity fallback = severity(config.getString("intel.defaultSeverity", "HIGH"));
        try {
            return load(feed, fallback);
        } catch (IOException ex) {
            EventLog.getInstance().log(LogLevel.WARN, "intel",
                    "Threat feed " + feed + " could not be read (" + ex.getMessage() + "); matching against nothing");
            return new ThreatIntel(List.of(), 0L);
        }
    }

    /** Reads from the classpath when the resource exists, else from the file system. */
    public static ThreatIntel load(String location, Severity fallbackSeverity) throws IOException {
        String text;
        InputStream stream = ThreatIntel.class.getClassLoader().getResourceAsStream(location);
        if (stream != null) {
            try (InputStream input = stream) {
                text = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            }
        } else if (Files.isRegularFile(Path.of(location))) {
            text = Files.readString(Path.of(location), StandardCharsets.UTF_8);
        } else {
            throw new IOException("feed not found: " + location);
        }
        return parse(text, location, fallbackSeverity);
    }

    public static ThreatIntel parse(String text, String source, Severity fallbackSeverity) {
        List<IntelEntry> parsed = new ArrayList<>();
        long skipped = 0;
        if (text != null) {
            for (String raw : text.split("\\R")) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\\s+");
                if (parts.length == 0 || parseCidr(parts[0]) == null) {
                    skipped++;
                    continue;
                }
                String label = parts.length > 1 ? parts[1] : "unlabelled";
                Severity severity = parts.length > 2 ? severity(parts[2]) : fallbackSeverity;
                parsed.add(new IntelEntry(parts[0], label,
                        severity == null ? Severity.HIGH : severity,
                        source == null ? "feed" : source));
            }
        }
        return new ThreatIntel(parsed, skipped);
    }

    public Optional<IntelEntry> match(String ip) {
        OptionalLong address = ipv4(ip);
        if (address.isEmpty()) {
            return Optional.empty();
        }
        long value = address.getAsLong();
        for (int i = 0; i < entries.size(); i++) {
            int prefix = prefixes[i];
            long mask = prefix == 0 ? 0L : (0xFFFF_FFFFL << (32 - prefix)) & 0xFFFF_FFFFL;
            if ((value & mask) == (networkStarts[i] & mask)) {
                return Optional.of(entries.get(i));
            }
        }
        return Optional.empty();
    }

    public int size() {
        return entries.size();
    }

    public long skippedLines() {
        return skipped;
    }

    public List<IntelEntry> entries() {
        return entries;
    }

    /** @return {network, prefix} or null when the value is not IPv4 */
    private static long[] parseCidr(String raw) {
        String address = raw;
        int prefix = 32;
        int slash = raw.indexOf('/');
        if (slash >= 0) {
            address = raw.substring(0, slash);
            try {
                prefix = Integer.parseInt(raw.substring(slash + 1));
            } catch (NumberFormatException ex) {
                return null;
            }
            if (prefix < 0 || prefix > 32) {
                return null;
            }
        }
        OptionalLong value = ipv4(address);
        return value.isEmpty() ? null : new long[]{value.getAsLong(), prefix};
    }

    private static OptionalLong ipv4(String raw) {
        if (raw == null) {
            return OptionalLong.empty();
        }
        String[] parts = raw.trim().split("\\.");
        if (parts.length != 4) {
            return OptionalLong.empty();
        }
        long value = 0L;
        for (String part : parts) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException ex) {
                return OptionalLong.empty();
            }
            if (octet < 0 || octet > 255) {
                return OptionalLong.empty();
            }
            value = (value << 8) | octet;
        }
        return OptionalLong.of(value);
    }

    private static Severity severity(String raw) {
        if (raw == null) {
            return Severity.HIGH;
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            return Severity.HIGH;
        }
    }
}
