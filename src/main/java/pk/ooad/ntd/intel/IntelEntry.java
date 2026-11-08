package pk.ooad.ntd.intel;

import pk.ooad.ntd.domain.Severity;

import java.time.Instant;

public record IntelEntry(String value, String label, Severity severity, String source,
                         IndicatorType type, String category, int confidence, Instant expiresAt) {

    public IntelEntry {
        value = value == null ? "" : value.trim();
        label = label == null || label.isBlank() ? "unlabelled" : label.trim();
        severity = severity == null ? Severity.HIGH : severity;
        source = source == null || source.isBlank() ? "feed" : source;
        type = type == null ? IndicatorType.infer(value) : type;
        category = category == null || category.isBlank() ? "unknown" : category.trim();
        confidence = Math.max(0, Math.min(100, confidence));
    }

    public boolean expired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }

    public String normalised() {
        return value.toLowerCase(java.util.Locale.ROOT);
    }
}
