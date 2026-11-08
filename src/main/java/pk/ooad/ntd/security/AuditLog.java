package pk.ooad.ntd.security;

import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * A bounded record of who did what.
 *
 * <p>Detection data answers "what happened on the network". This log answers
 * "who asked for it", which is the question an incident review asks next:
 * logins, refused logins, authorisation denials, simulation control, exports and
 * containment orders all land here with the acting account.</p>
 *
 * <p>The ring is capped by {@code audit.maxRecords}; the oldest entry is dropped
 * rather than letting a long running server grow without bound. Entries also go
 * to {@link EventLog} so an operator watching the log sees security events in
 * order with everything else.</p>
 */
public final class AuditLog {

    public enum Outcome {
        ALLOWED,
        DENIED,
        FAILED
    }

    public record Entry(long sequence, Instant timestamp, String actor, String action,
                        String target, String outcome, String detail) {
    }

    private final boolean enabled;
    private final int maxRecords;
    private final Deque<Entry> entries = new ArrayDeque<>();
    private long sequence;
    private long denied;
    private long failed;

    public AuditLog() {
        this(ConfigManager.getInstance());
    }

    public AuditLog(ConfigManager config) {
        this.enabled = Boolean.parseBoolean(config.getString("audit.enabled", "true"));
        this.maxRecords = Math.max(1, config.getInt("audit.maxRecords", 2000));
    }

    public AuditLog(boolean enabled, int maxRecords) {
        this.enabled = enabled;
        this.maxRecords = Math.max(1, maxRecords);
    }

    /** Records one attempt. A null actor means "not authenticated". */
    public synchronized void record(String actor, String action, String target, Outcome outcome, String detail) {
        if (!enabled || action == null || action.isBlank()) {
            return;
        }
        Outcome resolved = outcome == null ? Outcome.ALLOWED : outcome;
        String who = actor == null || actor.isBlank() ? "anonymous" : actor;
        Entry entry = new Entry(++sequence, Instant.now(), who, action,
                target == null ? "" : target, resolved.name(), detail == null ? "" : detail);
        entries.addLast(entry);
        while (entries.size() > maxRecords) {
            entries.removeFirst();
        }
        if (resolved == Outcome.DENIED) {
            denied++;
        } else if (resolved == Outcome.FAILED) {
            failed++;
        }
        LogLevel level = resolved == Outcome.ALLOWED ? LogLevel.INFO : LogLevel.WARN;
        EventLog.getInstance().log(level, "audit",
                who + " " + action + (entry.target().isEmpty() ? "" : " " + entry.target()) + " " + resolved);
    }

    /** Newest first. */
    public synchronized List<Entry> recent(int limit) {
        int capped = limit <= 0 ? maxRecords : Math.min(limit, maxRecords);
        List<Entry> rows = new ArrayList<>(Math.min(capped, entries.size()));
        var iterator = entries.descendingIterator();
        while (iterator.hasNext() && rows.size() < capped) {
            rows.add(iterator.next());
        }
        return rows;
    }

    public synchronized int size() {
        return entries.size();
    }

    public synchronized long deniedCount() {
        return denied;
    }

    public synchronized long failedCount() {
        return failed;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getMaxRecords() {
        return maxRecords;
    }

    public synchronized void reset() {
        entries.clear();
        sequence = 0L;
        denied = 0L;
        failed = 0L;
    }
}
