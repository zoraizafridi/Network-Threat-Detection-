package pk.ooad.ntd.export;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class ExportService {

    public record Table(String kind, List<String> columns, List<List<String>> rows) {
        public int count() {
            return rows.size();
        }
    }

    public record Rendered(String contentType, String body, String sha256, int count) {
    }

    public static final String CSV = "text/csv; charset=utf-8";
    public static final String JSON = "application/json; charset=utf-8";

    private final ObjectMapper mapper = new ObjectMapper();

    public Rendered render(Table table, String format) {
        if ("json".equalsIgnoreCase(format)) {
            return json(table);
        }
        return csv(table);
    }

    public Rendered csv(Table table) {
        StringBuilder out = new StringBuilder();
        row(out, table.columns());
        for (List<String> cells : table.rows()) {
            row(out, cells);
        }
        String body = out.toString();
        return new Rendered(CSV, body, sha256(body), table.count());
    }

    public Rendered json(Table table) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("kind", table.kind());
        envelope.put("generatedAt", Instant.now().toString());
        envelope.put("count", table.count());
        envelope.put("columns", table.columns());
        envelope.put("rows", table.rows());
        String body;
        try {
            body = mapper.writeValueAsString(envelope);
        } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
            throw new IllegalStateException("Unable to render " + table.kind(), ex);
        }
        return new Rendered(JSON, body, sha256(body), table.count());
    }

    public Map<String, Object> manifest(String kind, Object payload, int count) {
        String canonical;
        try {
            canonical = mapper.writeValueAsString(payload);
        } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
            throw new IllegalStateException("Unable to render the " + kind + " manifest", ex);
        }
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("kind", kind);
        manifest.put("formatVersion", 1);
        manifest.put("createdAt", Instant.now().toString());
        manifest.put("count", count);
        manifest.put("sha256", sha256(canonical));
        return manifest;
    }

    public String sha256(String text) {
        return sha256(text == null ? new byte[0] : text.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(byte[] content) {
        try {
            byte[] hashed = MessageDigest.getInstance("SHA-256").digest(content);
            StringBuilder out = new StringBuilder(hashed.length * 2);
            for (byte b : hashed) {
                out.append(Character.forDigit((b >> 4) & 0xF, 16));
                out.append(Character.forDigit(b & 0xF, 16));
            }
            return out.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private static void row(StringBuilder out, List<String> cells) {
        List<String> values = cells == null ? List.of() : cells;
        for (int index = 0; index < values.size(); index++) {
            if (index > 0) {
                out.append(',');
            }
            out.append(cell(values.get(index)));
        }
        out.append("\r\n");
    }

    static String cell(String value) {
        String text = neutralise(value == null ? "" : value);
        boolean quote = text.indexOf(',') >= 0 || text.indexOf('"') >= 0
                || text.indexOf('\n') >= 0 || text.indexOf('\r') >= 0
                || (!text.isEmpty() && (text.charAt(0) == ' ' || text.charAt(0) == '\t'));
        if (!quote) {
            return text;
        }
        return '"' + text.replace("\"", "\"\"") + '"';
    }

    private static String neutralise(String text) {
        if (text.isEmpty()) {
            return text;
        }
        char first = text.charAt(0);
        if (first == '=' || first == '+' || first == '-' || first == '@'
                || first == '\t' || first == '\r') {
            return "'" + text;
        }
        return text;
    }
}
