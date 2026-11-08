package pk.ooad.ntd.domain;

public enum AlertStatus {
    NEW,
    ACKNOWLEDGED,
    INVESTIGATING,
    RESOLVED,
    FALSE_POSITIVE;

    public boolean canMoveTo(AlertStatus next) {
        if (next == null || next == this) {
            return false;
        }
        return switch (this) {
            case NEW -> next == ACKNOWLEDGED || next == INVESTIGATING
                    || next == RESOLVED || next == FALSE_POSITIVE;
            case ACKNOWLEDGED -> next == INVESTIGATING || next == RESOLVED
                    || next == FALSE_POSITIVE || next == NEW;
            case INVESTIGATING -> next == ACKNOWLEDGED || next == RESOLVED
                    || next == FALSE_POSITIVE || next == NEW;
            case RESOLVED -> next == NEW;
            case FALSE_POSITIVE -> next == NEW;
        };
    }

    public boolean isClosed() {
        return this == RESOLVED || this == FALSE_POSITIVE;
    }

    public static AlertStatus parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return NEW;
        }
        try {
            return valueOf(raw.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return NEW;
        }
    }
}
