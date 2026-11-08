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
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public final class EventLog {
    private static final EventLog instance = new EventLog();
    private static final int FILE_BACKLOG = 8192;

    private final List<String> entries = Collections.synchronizedList(new ArrayList<>());
    private final Path logFile = Path.of("target", "event-log.log");
    private final BlockingQueue<String> pending = new ArrayBlockingQueue<>(FILE_BACKLOG);
    private boolean directoryReady;

    private EventLog() {
        Thread writer = new Thread(this::drain, "EventLog-writer");
        writer.setDaemon(true);
        writer.start();
    }

    public static EventLog getInstance() {
        return instance;
    }

    public synchronized void log(LogLevel level, String component, String msg) {
        Objects.requireNonNull(level, "level must not be null");
        String entry = Instant.now() + " [" + level + "] [" + safe(component) + "] " + safe(msg);
        entries.add(entry);
        pending.offer(entry);
    }

    public List<String> getEntries() {
        synchronized (entries) {
            return List.copyOf(entries);
        }
    }

    public synchronized void clear() {
        entries.clear();
        pending.clear();
        try {
            Files.deleteIfExists(logFile);
        } catch (IOException ignored) {
        }
    }

    private void drain() {
        while (true) {
            try {
                append(pending.take());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private synchronized void append(String entry) {
        try {
            if (!directoryReady) {
                Files.createDirectories(logFile.getParent());
                directoryReady = true;
            }
            Files.writeString(logFile, entry + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
        }
    }

    private String safe(String value) {
        if (value == null) {
            return "";
        }
        String flattened = value.replace('\r', ' ').replace('\n', ' ');
        return flattened.length() > 500 ? flattened.substring(0, 500) + "..." : flattened;
    }
}
