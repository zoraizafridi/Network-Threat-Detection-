package pk.ooad.ntd.security;

import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.function.Consumer;

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
    private Consumer<Entry> recorder = entry -> { };
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

    public synchronized void record(String actor, String action, String target, Outcome outcome, String detail) {
        if (!enabled || action == null || action.isBlank()) {
            return;
        }
        Outcome resolved = outcome == null ? Outcome.ALLOWED : outcome;
        String who = actor == null || actor.isBlank() ? "anonymous" : clean(actor, 64);
        Entry entry = new Entry(++sequence, Instant.now(), who, clean(action, 64),
                clean(target, 200), resolved.name(), clean(detail, 400));
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
        recorder.accept(entry);
    }

    private static String clean(String value, int max) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(Math.min(value.length(), max));
        for (int index = 0; index < value.length() && out.length() < max; index++) {
            char ch = value.charAt(index);
            out.append(ch < 0x20 || ch == 0x7F ? ' ' : ch);
        }
        return out.toString();
    }

    public void setRecorder(Consumer<Entry> sink) {
        this.recorder = sink == null ? entry -> { } : sink;
    }

    public synchronized void restore(List<Entry> restored) {
        if (restored == null || restored.isEmpty()) {
            return;
        }
        entries.clear();
        sequence = 0L;
        denied = 0L;
        failed = 0L;
        for (Entry entry : restored) {
            Entry copy = new Entry(++sequence, entry.timestamp(), entry.actor(), entry.action(),
                    entry.target(), entry.outcome(), entry.detail());
            entries.addLast(copy);
            while (entries.size() > maxRecords) {
                entries.removeFirst();
            }
            if (Outcome.DENIED.name().equals(copy.outcome())) {
                denied++;
            } else if (Outcome.FAILED.name().equals(copy.outcome())) {
                failed++;
            }
        }
    }

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
