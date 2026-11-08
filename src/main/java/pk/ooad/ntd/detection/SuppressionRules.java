package pk.ooad.ntd.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

public final class SuppressionRules {

    public record Rule(String id, String detector, String attackType, String sourceIp, String targetIp,
                       String maxSeverity, String note, String createdBy, String createdAt,
                       boolean enabled) {

        public Rule {
            id = text(id);
            detector = text(detector);
            attackType = text(attackType).toUpperCase(Locale.ROOT);
            sourceIp = text(sourceIp);
            targetIp = text(targetIp);
            maxSeverity = text(maxSeverity).toUpperCase(Locale.ROOT);
            note = text(note);
            createdBy = text(createdBy);
            createdAt = text(createdAt);
        }

        public boolean isBlank() {
            return detector.isEmpty() && attackType.isEmpty() && sourceIp.isEmpty() && targetIp.isEmpty();
        }

        public String describe() {
            List<String> parts = new ArrayList<>();
            parts.add("detector=" + (detector.isEmpty() ? "*" : detector));
            parts.add("type=" + (attackType.isEmpty() ? "*" : attackType));
            parts.add("source=" + (sourceIp.isEmpty() ? "*" : sourceIp));
            parts.add("target=" + (targetIp.isEmpty() ? "*" : targetIp));
            if (!maxSeverity.isEmpty()) {
                parts.add("maxSeverity=" + maxSeverity);
            }
            return String.join(" ", parts);
        }

        private static String text(String value) {
            return value == null ? "" : value.trim();
        }
    }

    private final Path file;
    private final boolean enabled;
    private final int maxRules;
    private final ObjectMapper mapper = new ObjectMapper();
    private final List<Rule> rules = new CopyOnWriteArrayList<>();
    private final AtomicBoolean faultLogged = new AtomicBoolean();

    public SuppressionRules() {
        this(ConfigManager.getInstance());
    }

    public SuppressionRules(ConfigManager config) {
        this(Path.of(config.getString("suppression.rules.file", "config/suppression-rules.json")),
                Boolean.parseBoolean(config.getString("suppression.enabled", "true")),
                config.getInt("suppression.maxRules", 200));
    }

    public SuppressionRules(Path file, boolean enabled, int maxRules) {
        this.file = file;
        this.enabled = enabled;
        this.maxRules = Math.max(1, maxRules);
        load();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Path file() {
        return file;
    }

    public List<Rule> rules() {
        return List.copyOf(rules);
    }

    public String match(Alert alert) {
        if (!enabled || alert == null || rules.isEmpty()) {
            return null;
        }
        for (Rule rule : rules) {
            if (rule.enabled() && matches(rule, alert)) {
                return rule.id();
            }
        }
        return null;
    }

    public Rule add(Rule requested, String actor) {
        if (requested == null || requested.isBlank()) {
            throw new IllegalArgumentException("A suppression rule must name a detector, a type, a source or a target");
        }
        if (rules.size() >= maxRules) {
            throw new IllegalArgumentException("The suppression table is full (" + maxRules + " rules)");
        }
        Rule stored = new Rule(
                requested.id().isEmpty() ? "sr-" + UUID.randomUUID().toString().substring(0, 8) : requested.id(),
                requested.detector(),
                requested.attackType(),
                requested.sourceIp(),
                requested.targetIp(),
                requested.maxSeverity(),
                requested.note(),
                actor == null || actor.isBlank() ? requested.createdBy() : actor,
                requested.createdAt().isEmpty() ? Instant.now().toString() : requested.createdAt(),
                requested.enabled());
        rules.add(stored);
        save();
        return stored;
    }

    public Rule remove(String id) {
        if (id == null || id.isBlank()) {
            return null;
        }
        for (Rule rule : rules) {
            if (rule.id().equals(id)) {
                rules.remove(rule);
                save();
                return rule;
            }
        }
        return null;
    }

    public void clear() {
        rules.clear();
    }

    private static boolean matches(Rule rule, Alert alert) {
        if (!rule.detector().isEmpty() && !rule.detector().equalsIgnoreCase(alert.getDetectorName())) {
            return false;
        }
        if (!rule.attackType().isEmpty() && !rule.attackType().equalsIgnoreCase(
                alert.getAttackType() == null ? "" : alert.getAttackType().name())) {
            return false;
        }
        if (!rule.sourceIp().isEmpty() && !rule.sourceIp().equals(alert.getSourceIp())) {
            return false;
        }
        if (!rule.targetIp().isEmpty() && !rule.targetIp().equals(alert.getTargetIp())) {
            return false;
        }
        if (!rule.maxSeverity().isEmpty()) {
            int ceiling = rank(rule.maxSeverity());
            if (ceiling <= 0 || rank(alert.getSeverity()) > ceiling) {
                return false;
            }
        }
        return true;
    }

    private static int rank(Severity severity) {
        if (severity == null) {
            return 0;
        }
        return switch (severity) {
            case LOW -> 1;
            case HIGH -> 2;
            case CRITICAL -> 3;
        };
    }

    private static int rank(String raw) {
        if (raw == null || raw.isBlank()) {
            return 0;
        }
        try {
            return rank(Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException ex) {
            return 0;
        }
    }

    private void load() {
        if (file == null || !Files.isRegularFile(file)) {
            return;
        }
        try {
            JsonNode root = mapper.readTree(Files.readString(file));
            JsonNode rows = root.isArray() ? root : root.path("rules");
            if (!rows.isArray()) {
                return;
            }
            for (JsonNode row : rows) {
                Rule rule = read(row);
                if (rule != null && !rule.isBlank() && rules.size() < maxRules) {
                    rules.add(rule);
                }
            }
        } catch (IOException | RuntimeException ex) {
            report("Could not read " + file + " (" + ex + "); the suppression table starts empty");
        }
    }

    private void save() {
        if (file == null) {
            return;
        }
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            ObjectNode root = mapper.createObjectNode();
            root.put("version", 1);
            ArrayNode rows = root.putArray("rules");
            for (Rule rule : rules) {
                ObjectNode row = rows.addObject();
                row.put("id", rule.id());
                row.put("detector", rule.detector());
                row.put("attackType", rule.attackType());
                row.put("sourceIp", rule.sourceIp());
                row.put("targetIp", rule.targetIp());
                row.put("maxSeverity", rule.maxSeverity());
                row.put("note", rule.note());
                row.put("createdBy", rule.createdBy());
                row.put("createdAt", rule.createdAt());
                row.put("enabled", rule.enabled());
            }
            Files.writeString(file, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root));
        } catch (IOException | RuntimeException ex) {
            report("Could not write " + file + " (" + ex + "); the rules live in memory only");
        }
    }

    private static Rule read(JsonNode row) {
        if (row == null || !row.isObject()) {
            return null;
        }
        return new Rule(
                row.path("id").asText(""),
                row.path("detector").asText(""),
                row.path("attackType").asText(""),
                row.path("sourceIp").asText(""),
                row.path("targetIp").asText(""),
                row.path("maxSeverity").asText(""),
                row.path("note").asText(""),
                row.path("createdBy").asText(""),
                row.path("createdAt").asText(""),
                !row.has("enabled") || row.path("enabled").asBoolean(true));
    }

    private void report(String message) {
        if (faultLogged.compareAndSet(false, true)) {
            EventLog.getInstance().log(LogLevel.WARN, "suppression", message);
        }
    }
}
