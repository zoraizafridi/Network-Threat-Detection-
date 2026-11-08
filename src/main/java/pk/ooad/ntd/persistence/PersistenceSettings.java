package pk.ooad.ntd.persistence;

import pk.ooad.ntd.util.ConfigManager;

import java.nio.file.Path;

/**
 * Knobs for the durable store, read from {@code config.properties}.
 *
 * <p>Every key can also be given as a system property with an {@code ntd.}
 * prefix, so a container or a test can turn the store on without editing the
 * packaged file: {@code -Dntd.persistence.enabled=true}. That override is
 * checked first and wins over the properties file.</p>
 *
 * <p>A missing or unparsable value falls back to its default here rather than
 * throwing. Detection is the primary job of this process; a typo in a
 * persistence key must not stop the detector from starting. The rest of the
 * code base keeps the strict {@link ConfigManager} behaviour.</p>
 */
public record PersistenceSettings(
        boolean enabled,
        Path databasePath,
        int queueCapacity,
        int batchSize,
        long flushIntervalMillis,
        int retentionMinutes,
        int sweepMinutes) {

    private static final String OVERRIDE_PREFIX = "ntd.";

    public static PersistenceSettings from(ConfigManager config) {
        Path directory = Path.of(stringValue(config, "persistence.dir", "data"));
        String file = stringValue(config, "persistence.file", "ntd.db");
        return new PersistenceSettings(
                Boolean.parseBoolean(stringValue(config, "persistence.enabled", "false")),
                directory.resolve(file),
                Math.max(16, intValue(config, "persistence.queueCapacity", 5000)),
                Math.max(1, intValue(config, "persistence.batchSize", 200)),
                Math.max(50, intValue(config, "persistence.flushIntervalMillis", 500)),
                Math.max(1, intValue(config, "persistence.retentionMinutes", 24 * 60)),
                Math.max(1, intValue(config, "persistence.sweepMinutes", 5)));
    }

    /** The store switched off, used when the service refuses to start. */
    public static PersistenceSettings disabled() {
        return new PersistenceSettings(false, Path.of("data").resolve("ntd.db"), 5000, 200, 500, 24 * 60, 5);
    }

    /** Same settings pointed at another file, which is what the tests use. */
    public PersistenceSettings withDatabasePath(Path path) {
        return new PersistenceSettings(enabled, path, queueCapacity, batchSize, flushIntervalMillis,
                retentionMinutes, sweepMinutes);
    }

    public PersistenceSettings withEnabled(boolean value) {
        return new PersistenceSettings(value, databasePath, queueCapacity, batchSize, flushIntervalMillis,
                retentionMinutes, sweepMinutes);
    }

    public PersistenceSettings withQueueCapacity(int capacity) {
        return new PersistenceSettings(enabled, databasePath, capacity, batchSize, flushIntervalMillis,
                retentionMinutes, sweepMinutes);
    }

    public PersistenceSettings withBatchSize(int size) {
        return new PersistenceSettings(enabled, databasePath, queueCapacity, size, flushIntervalMillis,
                retentionMinutes, sweepMinutes);
    }

    public PersistenceSettings withRetentionMinutes(int minutes) {
        return new PersistenceSettings(enabled, databasePath, queueCapacity, batchSize, flushIntervalMillis,
                minutes, sweepMinutes);
    }

    private static String stringValue(ConfigManager config, String key, String fallback) {
        String override = System.getProperty(OVERRIDE_PREFIX + key);
        String value = override != null ? override : config.getString(key, fallback);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static int intValue(ConfigManager config, String key, int fallback) {
        String raw = stringValue(config, key, null);
        if (raw == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }
}
