package pk.ooad.ntd.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class EventLog {
    private static final EventLog instance = new EventLog();
    private final List<String> entries = Collections.synchronizedList(new ArrayList<>());
    private final Path logFile = Path.of("target", "event-log.log");

    private EventLog() {
    }

    public static EventLog getInstance() {
        return instance;
    }

    public synchronized void log(LogLevel level, String component, String msg) {
        Objects.requireNonNull(level, "level must not be null");
        String entry = Instant.now() + " [" + level + "] [" + safe(component) + "] " + safe(msg);
        entries.add(entry);
        try {
            Files.createDirectories(logFile.getParent());
            Files.writeString(logFile, entry + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // In-memory entries remain available if the optional file cannot be written.
        }
    }

    public List<String> getEntries() {
        synchronized (entries) {
            return List.copyOf(entries);
        }
    }

    public synchronized void clear() {
        entries.clear();
        try {
            Files.deleteIfExists(logFile);
        } catch (IOException ignored) {
            // Clearing the in-memory log must still succeed.
        }
    }

    private String safe(String value) {
        return value != null ? value : "";
    }
}
