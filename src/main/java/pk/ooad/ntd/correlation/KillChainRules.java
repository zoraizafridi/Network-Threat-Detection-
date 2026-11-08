package pk.ooad.ntd.correlation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class KillChainRules {

    public static final String DEFAULT_FILE = "config/kill-chain.json";

    public record Chain(String id, String name, List<AttackType> stages, int windowSeconds,
                        Severity severity, String note) {

        public Chain {
            stages = stages == null ? List.of() : List.copyOf(stages);
        }

        public String path() {
            List<String> names = new ArrayList<>();
            for (AttackType stage : stages) {
                names.add(stage.name());
            }
            return String.join(" then ", names);
        }

        public String describe() {
            return name + " (" + path() + ", within " + windowSeconds + "s)";
        }
    }

    private final List<Chain> rules;
    private final Path file;
    private final String problem;

    public KillChainRules() {
        this(ConfigManager.getInstance());
    }

    public KillChainRules(ConfigManager config) {
        this(config, resolve(config));
    }

    KillChainRules(ConfigManager config, Path file) {
        this.file = file;
        Loaded loaded = load(file);
        this.rules = loaded.chains().isEmpty() ? defaults() : loaded.chains();
        this.problem = loaded.problem();
    }

    public KillChainRules(List<Chain> rules, Path file) {
        this.rules = rules == null || rules.isEmpty() ? defaults() : List.copyOf(rules);
        this.file = file;
        this.problem = "";
    }

    public static List<Chain> defaults() {
        return List.of(new Chain("recon-to-exfil", "Recon to exfiltration",
                List.of(AttackType.PORT_SCAN, AttackType.BRUTE_FORCE, AttackType.DATA_TRANSFER),
                900, Severity.CRITICAL, "Scan, then credentials, then a transfer out"));
    }

    public List<Chain> rules() {
        return rules;
    }

    public int size() {
        return rules.size();
    }

    public Path file() {
        return file;
    }

    public String problem() {
        return problem;
    }

    private static Path resolve(ConfigManager config) {
        String raw = config.getString("correlation.killChain.file", DEFAULT_FILE);
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return Paths.get(raw.trim());
    }

    private record Loaded(List<Chain> chains, String problem) {
    }

    private static Loaded load(Path file) {
        if (file == null || !Files.isRegularFile(file)) {
            return new Loaded(List.of(), "");
        }
        JsonNode root;
        try {
            root = new ObjectMapper().readTree(Files.readString(file));
        } catch (IOException | RuntimeException ex) {
            return new Loaded(List.of(), file + " could not be read: " + ex.getMessage());
        }
        JsonNode array = root.path("chains");
        if (!array.isArray()) {
            return new Loaded(List.of(), file + " has no chains array");
        }
        List<Chain> parsed = new ArrayList<>();
        List<String> refused = new ArrayList<>();
        for (JsonNode node : array) {
            Chain chain = parse(node, refused);
            if (chain != null) {
                parsed.add(chain);
            }
        }
        String problem = refused.isEmpty() ? "" : String.join("; ", refused);
        return new Loaded(List.copyOf(parsed), problem);
    }

    private static Chain parse(JsonNode node, List<String> refused) {
        String id = node.path("id").asText("").trim();
        String name = node.path("name").asText("").trim();
        if (id.isEmpty()) {
            id = name.isEmpty() ? "chain-" + (refused.size() + 1) : name;
        }
        List<AttackType> stages = new ArrayList<>();
        for (JsonNode stage : node.path("stages")) {
            String raw = stage.asText("").trim().toUpperCase(Locale.ROOT);
            try {
                stages.add(AttackType.valueOf(raw));
            } catch (IllegalArgumentException ex) {
                refused.add(id + " names unknown stage " + raw);
                return null;
            }
        }
        if (stages.size() < 2) {
            refused.add(id + " needs at least two stages");
            return null;
        }
        int window = node.path("windowSeconds").asInt(900);
        return new Chain(id, name.isEmpty() ? id : name, stages, Math.max(1, window),
                severity(node.path("severity").asText("CRITICAL")), node.path("note").asText(""));
    }

    private static Severity severity(String raw) {
        try {
            return Severity.valueOf(raw == null ? "CRITICAL" : raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return Severity.CRITICAL;
        }
    }
}
