package pk.ooad.ntd.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public final class ConfigManager {
    private static volatile ConfigManager instance;
    private final Properties props = new Properties();

    private ConfigManager() {
        try (InputStream input = ConfigManager.class.getClassLoader().getResourceAsStream("config.properties")) {
            if (input != null) props.load(input);
        } catch (IOException | IllegalArgumentException e) {
            throw new InvalidConfigException("Unable to load classpath configuration file: config.properties", e);
        }
    }

    public static ConfigManager getInstance() {
        if (instance == null) {
            synchronized (ConfigManager.class) {
                if (instance == null) {
                    instance = new ConfigManager();
                }
            }
        }
        return instance;
    }

    public synchronized void load(String path) {
        if (path == null || path.isBlank()) {
            throw new InvalidConfigException("Configuration file path must not be blank");
        }
        Path configPath = Path.of(path);
        if (!Files.isRegularFile(configPath)) {
            throw new InvalidConfigException("Configuration file not found: " + path);
        }
        Properties loaded = new Properties();
        try (InputStream input = Files.newInputStream(configPath)) {
            loaded.load(input);
        } catch (IOException | IllegalArgumentException e) {
            throw new InvalidConfigException("Unable to load configuration file: " + path, e);
        }
        props.clear();
        props.putAll(loaded);
    }

    public int getInt(String key, int def) {
        String value = valueFor(key);
        if (value == null) return def;
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw invalidValue(key, value, "integer", e);
        }
    }

    public double getDouble(String key, double def) {
        String value = valueFor(key);
        if (value == null) return def;
        try {
            double result = Double.parseDouble(value);
            if (!Double.isFinite(result)) throw new NumberFormatException("not finite");
            return result;
        } catch (NumberFormatException e) {
            throw invalidValue(key, value, "double", e);
        }
    }

    public String getString(String key, String def) {
        String value = valueFor(key);
        return value != null ? value : def;
    }

    public List<String> getList(String key) {
        String value = valueFor(key);
        if (value == null || value.isBlank()) return List.of();
        return Arrays.stream(value.split(",", -1))
                .map(String::trim)
                .filter(item -> !item.isEmpty())
                .toList();
    }

    /**
     * Resolves a key. A system property named {@code ntd.<key>} wins over the
     * properties file, which is how a demo or a test turns a single feature on
     * without editing the packaged configuration:
     * {@code -Dntd.detection.beaconing.enabled=true}.
     */
    private String valueFor(String key) {
        if (key == null || key.isBlank()) {
            throw new InvalidConfigException("Configuration key must not be blank");
        }
        String override = System.getProperty("ntd." + key);
        if (override != null) {
            return override.trim();
        }
        String value = props.getProperty(key);
        return value != null ? value.trim() : null;
    }

    private InvalidConfigException invalidValue(String key, String value, String expected, Throwable cause) {
        return new InvalidConfigException("Invalid " + expected + " value for configuration key '" + key + "': " + value, cause);
    }
}
