package pk.ooad.ntd.intel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ThreatIntel {

    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*");
    private static final Pattern DIGEST = Pattern.compile("\\b[0-9a-fA-F]{64}\\b");
    private static final ObjectMapper JSON = new ObjectMapper();

    private final List<IntelEntry> entries;
    private final List<IntelEntry> addresses;
    private final long[] networkStarts;
    private final int[] prefixes;
    private final Map<String, IntelEntry> domains;
    private final Map<String, IntelEntry> digests;
    private final long skipped;
    private final long expired;
    private final String source;

    private ThreatIntel(List<IntelEntry> entries, long skipped, long expired, String source) {
        this.entries = List.copyOf(entries);
        this.skipped = skipped;
        this.expired = expired;
        this.source = source == null ? "none" : source;
        List<IntelEntry> ip = new ArrayList<>();
        Map<String, IntelEntry> byDomain = new LinkedHashMap<>();
        Map<String, IntelEntry> byDigest = new LinkedHashMap<>();
        for (IntelEntry entry : this.entries) {
            switch (entry.type()) {
                case IP -> ip.add(entry);
                case DOMAIN -> byDomain.putIfAbsent(entry.normalised(), entry);
                case SHA256 -> byDigest.putIfAbsent(entry.normalised(), entry);
            }
        }
        this.addresses = List.copyOf(ip);
        this.domains = Map.copyOf(byDomain);
        this.digests = Map.copyOf(byDigest);
        this.networkStarts = new long[this.addresses.size()];
        this.prefixes = new int[this.addresses.size()];
        for (int i = 0; i < this.addresses.size(); i++) {
            long[] parsed = parseCidr(this.addresses.get(i).value());
            this.networkStarts[i] = parsed == null ? 0L : parsed[0];
            this.prefixes[i] = parsed == null ? 32 : (int) parsed[1];
        }
    }

    public static ThreatIntel fromConfig() {
        ConfigManager config = ConfigManager.getInstance();
        String feed = config.getString("intel.feed", "threat-intel.json");
        Severity fallback = severity(config.getString("intel.defaultSeverity", "HIGH"));
        try {
            return load(feed, fallback);
        } catch (IOException ex) {
            EventLog.getInstance().log(LogLevel.WARN, "intel",
                    "Threat feed " + feed + " could not be read (" + ex.getMessage() + "); matching against nothing");
            return empty(feed);
        }
    }

    public static ThreatIntel empty(String source) {
        return new ThreatIntel(List.of(), 0L, 0L, source);
    }

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
        return parse(text, source, fallbackSeverity, Instant.now());
    }

    public static ThreatIntel parse(String text, String source, Severity fallbackSeverity, Instant now) {
        if (text == null || text.isBlank()) {
            return empty(source);
        }
        String head = text.stripLeading();
        if (head.startsWith("[") || head.startsWith("{")) {
            return parseJson(text, source, fallbackSeverity, now == null ? Instant.now() : now);
        }
        return parseLines(text, source, fallbackSeverity, now == null ? Instant.now() : now);
    }

    public Optional<IntelEntry> match(String ip) {
        OptionalLong address = ipv4(ip);
        if (address.isEmpty()) {
            return Optional.empty();
        }
        long value = address.getAsLong();
        for (int i = 0; i < addresses.size(); i++) {
            int prefix = prefixes[i];
            long mask = prefix == 0 ? 0L : (0xFFFF_FFFFL << (32 - prefix)) & 0xFFFF_FFFFL;
            if ((value & mask) == (networkStarts[i] & mask)) {
                return Optional.of(addresses.get(i));
            }
        }
        return Optional.empty();
    }

    public Optional<IntelEntry> matchDomain(String host) {
        if (host == null || domains.isEmpty()) {
            return Optional.empty();
        }
        String name = host.trim().toLowerCase(Locale.ROOT);
        while (name.endsWith(".")) {
            name = name.substring(0, name.length() - 1);
        }
        String candidate = name;
        while (!candidate.isEmpty()) {
            IntelEntry hit = domains.get(candidate);
            if (hit != null) {
                return Optional.of(hit);
            }
            int dot = candidate.indexOf('.');
            if (dot < 0) {
                return Optional.empty();
            }
            candidate = candidate.substring(dot + 1);
        }
        return Optional.empty();
    }

    public Optional<IntelEntry> matchHash(String digest) {
        if (digest == null || digests.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(digests.get(digest.trim().toLowerCase(Locale.ROOT)));
    }

    public Optional<IntelEntry> matchPayload(String payload) {
        if (payload == null || payload.isBlank()) {
            return Optional.empty();
        }
        Matcher digests2 = DIGEST.matcher(payload);
        while (digests2.find()) {
            Optional<IntelEntry> hit = matchHash(digests2.group());
            if (hit.isPresent()) {
                return hit;
            }
        }
        Matcher tokens = TOKEN.matcher(payload);
        while (tokens.find()) {
            String token = tokens.group();
            if (token.indexOf('.') >= 0) {
                Optional<IntelEntry> hit = matchDomain(token);
                if (hit.isPresent()) {
                    return hit;
                }
            }
        }
        return Optional.empty();
    }

    public static Severity severityFor(String category, int confidence, Severity fallback) {
        if (category == null || category.isBlank() || "unknown".equalsIgnoreCase(category.trim())) {
            return fallback == null ? Severity.HIGH : fallback;
        }
        Severity base = switch (category.trim().toLowerCase(Locale.ROOT)) {
            case "c2", "command-and-control", "malware", "ransomware", "phishing", "exploit-kit" -> Severity.CRITICAL;
            case "scanner", "scanning", "botnet", "brute-force", "ddos", "exploit" -> Severity.HIGH;
            default -> Severity.LOW;
        };
        if (confidence >= 80) {
            return base;
        }
        if (confidence >= 50) {
            return base == Severity.CRITICAL ? Severity.HIGH : Severity.LOW;
        }
        return Severity.LOW;
    }

    public int size() {
        return entries.size();
    }

    public int addressCount() {
        return addresses.size();
    }

    public int domainCount() {
        return domains.size();
    }

    public int digestCount() {
        return digests.size();
    }

    public long skippedLines() {
        return skipped;
    }

    public long expiredEntries() {
        return expired;
    }

    public String source() {
        return source;
    }

    public List<IntelEntry> entries() {
        return entries;
    }

    private static ThreatIntel parseLines(String text, String source, Severity fallbackSeverity, Instant now) {
        List<IntelEntry> parsed = new ArrayList<>();
        long skipped = 0;
        long expired = 0;
        for (String raw : text.split("\\R")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split("\\s+");
            IndicatorType type = IndicatorType.infer(parts[0]);
            if (!valid(type, parts[0])) {
                skipped++;
                continue;
            }
            String label = parts.length > 1 ? parts[1] : "unlabelled";
            Severity severity = parts.length > 2 ? severity(parts[2], fallbackSeverity) : fallbackSeverity;
            IntelEntry entry = new IntelEntry(parts[0], label,
                    severity == null ? Severity.HIGH : severity,
                    source == null ? "feed" : source, type,
                    parts.length > 1 ? parts[1] : "unknown", 50, null);
            if (entry.expired(now)) {
                expired++;
                continue;
            }
            parsed.add(entry);
        }
        return new ThreatIntel(parsed, skipped, expired, source);
    }

    private static ThreatIntel parseJson(String text, String source, Severity fallback, Instant now) {
        JsonNode root;
        try {
            root = JSON.readTree(text);
        } catch (IOException ex) {
            EventLog.getInstance().log(LogLevel.WARN, "intel",
                    "Threat feed " + source + " is not valid JSON (" + ex.getMessage() + "); matching against nothing");
            return empty(source);
        }
        JsonNode array = root.isArray() ? root : root.path("indicators");
        if (!array.isArray()) {
            EventLog.getInstance().log(LogLevel.WARN, "intel",
                    "Threat feed " + source + " holds no array of indicators; matching against nothing");
            return empty(source);
        }
        List<IntelEntry> parsed = new ArrayList<>();
        long skipped = 0;
        long expired = 0;
        for (JsonNode node : array) {
            String value = node.path("value").asText("").trim();
            IndicatorType type = IndicatorType.fromName(node.path("type").asText(""));
            if (type == null) {
                type = IndicatorType.infer(value);
            }
            if (!valid(type, value)) {
                skipped++;
                continue;
            }
            Instant expiresAt = parseInstant(node.path("expires").asText(""));
            if (expiresAt == EXPIRED_PARSE_FAILED) {
                skipped++;
                continue;
            }
            String category = node.path("category").asText("unknown");
            int confidence = node.path("confidence").asInt(50);
            String stated = node.path("severity").asText("");
            Severity severity = stated.isBlank()
                    ? severityFor(category, confidence, fallback)
                    : severity(stated, fallback);
            IntelEntry entry = new IntelEntry(value, node.path("label").asText(""), severity,
                    source, type, category, confidence, expiresAt);
            if (entry.expired(now)) {
                expired++;
                continue;
            }
            parsed.add(entry);
        }
        return new ThreatIntel(parsed, skipped, expired, source);
    }

    private static final Instant EXPIRED_PARSE_FAILED = Instant.MIN;

    private static Instant parseInstant(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(raw.trim());
        } catch (DateTimeParseException ex) {
            return EXPIRED_PARSE_FAILED;
        }
    }

    private static boolean valid(IndicatorType type, String value) {
        if (value == null || value.isBlank() || !type.accepts(value)) {
            return false;
        }
        return type != IndicatorType.IP || parseCidr(value.trim()) != null;
    }

    private static long[] parseCidr(String raw) {
        if (raw == null) {
            return null;
        }
        String address = raw.trim();
        int prefix = 32;
        int slash = address.indexOf('/');
        if (slash >= 0) {
            try {
                prefix = Integer.parseInt(address.substring(slash + 1));
            } catch (NumberFormatException ex) {
                return null;
            }
            address = address.substring(0, slash);
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
        return severity(raw, Severity.HIGH);
    }

    private static Severity severity(String raw, Severity fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback == null ? Severity.HIGH : fallback;
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return fallback == null ? Severity.HIGH : fallback;
        }
    }
}
