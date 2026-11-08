package pk.ooad.ntd.intel;

import java.util.Locale;
import java.util.regex.Pattern;

public enum IndicatorType {

    IP, DOMAIN, SHA256;

    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+");
    private static final Pattern HASH_PATTERN = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern IPV4_PATTERN = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}(/\\d{1,2})?");

    public static IndicatorType fromName(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "ip", "ipv4", "cidr", "network" -> IP;
            case "domain", "hostname", "fqdn", "url" -> DOMAIN;
            case "sha256", "hash", "file" -> SHA256;
            default -> null;
        };
    }

    public static IndicatorType infer(String value) {
        if (value == null) {
            return IP;
        }
        String trimmed = value.trim().toLowerCase(Locale.ROOT);
        if (HASH_PATTERN.matcher(trimmed).matches()) {
            return SHA256;
        }
        if (IPV4_PATTERN.matcher(trimmed).matches()) {
            return IP;
        }
        if (DOMAIN_PATTERN.matcher(trimmed).matches()) {
            return DOMAIN;
        }
        return IP;
    }

    public boolean accepts(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String trimmed = value.trim().toLowerCase(Locale.ROOT);
        return switch (this) {
            case IP -> true;
            case DOMAIN -> DOMAIN_PATTERN.matcher(trimmed).matches();
            case SHA256 -> HASH_PATTERN.matcher(trimmed).matches();
        };
    }
}
