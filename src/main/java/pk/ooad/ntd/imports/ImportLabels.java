package pk.ooad.ntd.imports;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class ImportLabels {

    private static final int MAX_PROBLEMS = 20;
    private static final String UID = "uid";
    private static final String LABEL = "label";

    private ImportLabels() {
    }

    public record Parsed(Map<String, String> labels, List<String> problems) {

        public Parsed {
            labels = labels == null ? Map.of() : Map.copyOf(labels);
            problems = problems == null ? List.of() : List.copyOf(problems);
        }

        public int size() {
            return labels.size();
        }
    }

    public static Parsed parse(String content) {
        return parse(content, null);
    }

    public static Parsed parse(String content, String source) {
        String where = source == null || source.isBlank() ? "labels" : source;
        Map<String, String> labels = new LinkedHashMap<>();
        List<String> problems = new ArrayList<>();
        if (content == null || content.isBlank()) {
            return new Parsed(labels, problems);
        }
        String[] lines = content.split("\\R");
        int uidColumn = 0;
        int labelColumn = 1;
        boolean headerRead = false;
        int duplicates = 0;
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index];
            if (line.isBlank() || line.trim().startsWith("#")) {
                continue;
            }
            List<String> cells = cells(line);
            if (cells.size() < 2) {
                addProblem(problems, where + " line " + (index + 1) + ": expected two columns, found "
                        + cells.size());
                continue;
            }
            if (!headerRead) {
                headerRead = true;
                int resolvedUid = indexOf(cells, UID);
                int resolvedLabel = indexOf(cells, LABEL);
                if (resolvedUid >= 0 && resolvedLabel >= 0) {
                    uidColumn = resolvedUid;
                    labelColumn = resolvedLabel;
                    continue;
                }
            }
            if (uidColumn >= cells.size() || labelColumn >= cells.size()) {
                addProblem(problems, where + " line " + (index + 1) + ": not enough columns for uid and label");
                continue;
            }
            String uid = cells.get(uidColumn);
            String label = normalise(cells.get(labelColumn));
            if (uid.isEmpty() || label.isEmpty()) {
                addProblem(problems, where + " line " + (index + 1) + ": empty uid or label");
                continue;
            }
            if (labels.put(uid, label) != null) {
                duplicates++;
            }
        }
        if (duplicates > 0) {
            addProblem(problems, where + ": " + duplicates + " repeated uids; the last label for each one wins");
        }
        if (labels.isEmpty() && problems.isEmpty()) {
            addProblem(problems, where + ": no uid,label pairs were found");
        }
        return new Parsed(labels, problems);
    }

    static String normalise(String raw) {
        if (raw == null) {
            return "";
        }
        String trimmed = raw.trim();
        if (trimmed.length() >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        trimmed = trimmed.replace(' ', '_').replace('-', '_').toUpperCase(Locale.ROOT);
        return trimmed;
    }

    private static List<String> cells(String line) {
        String[] parts = line.split(",", -1);
        List<String> cells = new ArrayList<>(parts.length);
        for (String part : parts) {
            String cell = part.trim();
            if (cell.length() >= 2 && cell.startsWith("\"") && cell.endsWith("\"")) {
                cell = cell.substring(1, cell.length() - 1).trim();
            }
            cells.add(cell);
        }
        return cells;
    }

    private static int indexOf(List<String> cells, String name) {
        for (int i = 0; i < cells.size(); i++) {
            if (name.equalsIgnoreCase(cells.get(i).trim())) {
                return i;
            }
        }
        return -1;
    }

    private static void addProblem(List<String> problems, String message) {
        if (problems.size() < MAX_PROBLEMS) {
            problems.add(message);
        }
    }
}
