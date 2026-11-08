package pk.ooad.ntd.persistence;

import pk.ooad.ntd.flows.FlowRecord;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class TableSpecs {

    static final TableSpec<FlowRecord> FLOW = new TableSpec<>() {
        @Override
        public String table() {
            return "flows";
        }

        @Override
        public String columns() {
            return "id, src_ip, dst_ip, src_port, dst_port, protocol, bytes_out, bytes_in, packets, "
                    + "start_ms, end_ms, flags, label, simulated, ended";
        }

        @Override
        public String timestampColumn() {
            return "start_ms";
        }

        @Override
        public String insertSql() {
            return "INSERT OR REPLACE INTO flows (" + columns() + ")"
                    + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
        }

        @Override
        public void bind(PreparedStatement statement, FlowRecord row) throws SQLException {
            statement.setString(1, text(row.id()));
            statement.setString(2, text(row.srcIp()));
            statement.setString(3, text(row.dstIp()));
            statement.setInt(4, row.srcPort());
            statement.setInt(5, row.dstPort());
            statement.setString(6, text(row.protocol()));
            statement.setLong(7, row.bytesOut());
            statement.setLong(8, row.bytesIn());
            statement.setLong(9, row.packets());
            statement.setLong(10, millis(row.startTime()));
            statement.setLong(11, millis(row.endTime()));
            statement.setString(12, row.flags() == null ? "" : String.join(",", row.flags()));
            statement.setString(13, text(row.label()));
            statement.setInt(14, row.simulated() ? 1 : 0);
            statement.setInt(15, row.ended() ? 1 : 0);
        }

        @Override
        public FlowRecord map(ResultSet rows) throws SQLException {
            return new FlowRecord(rows.getString("id"), rows.getString("src_ip"),
                    rows.getString("dst_ip"), rows.getInt("src_port"), rows.getInt("dst_port"),
                    rows.getString("protocol"), rows.getLong("bytes_out"), rows.getLong("bytes_in"),
                    rows.getLong("packets"), instant(rows.getLong("start_ms")),
                    instant(rows.getLong("end_ms")), flags(rows.getString("flags")),
                    rows.getString("label"), rows.getInt("simulated") == 1,
                    rows.getInt("ended") == 1);
        }

        @Override
        public long timestamp(FlowRecord row) {
            return millis(row.startTime());
        }
    };

    static final TableSpec<AlertRecord> ALERT = new TableSpec<>() {
        @Override
        public String table() {
            return "alerts";
        }

        @Override
        public String columns() {
            return "id, ts_ms, severity, attack_type, source_ip, target_ip, detector, description, simulated, "
                    + "occurrences, first_seen_ms, last_seen_ms, status";
        }

        @Override
        public String timestampColumn() {
            return "ts_ms";
        }

        @Override
        public String insertSql() {
            return "INSERT OR REPLACE INTO alerts (" + columns() + ")"
                    + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        }

        @Override
        public void bind(PreparedStatement statement, AlertRecord row) throws SQLException {
            statement.setString(1, text(row.id()));
            statement.setLong(2, millis(row.timestamp()));
            statement.setString(3, text(row.severity()));
            statement.setString(4, text(row.attackType()));
            statement.setString(5, text(row.sourceIp()));
            statement.setString(6, text(row.targetIp()));
            statement.setString(7, text(row.detector()));
            statement.setString(8, text(row.description()));
            statement.setInt(9, row.simulated() ? 1 : 0);
            statement.setInt(10, Math.max(1, row.occurrences()));
            statement.setLong(11, millis(row.firstSeen()));
            statement.setLong(12, millis(row.lastSeen()));
            statement.setString(13, text(row.status()));
        }

        @Override
        public AlertRecord map(ResultSet rows) throws SQLException {
            return new AlertRecord(rows.getString("id"), instant(rows.getLong("ts_ms")),
                    rows.getString("severity"), rows.getString("attack_type"),
                    rows.getString("source_ip"), rows.getString("target_ip"),
                    rows.getString("detector"), rows.getString("description"),
                    rows.getInt("simulated") == 1, rows.getInt("occurrences"),
                    instant(rows.getLong("first_seen_ms")), instant(rows.getLong("last_seen_ms")),
                    rows.getString("status"));
        }

        @Override
        public long timestamp(AlertRecord row) {
            return millis(row.timestamp());
        }
    };

    static final TableSpec<IncidentRecord> INCIDENT = new TableSpec<>() {
        @Override
        public String table() {
            return "incidents";
        }

        @Override
        public String columns() {
            return "id, opened_ms, source_ip, status, highest_severity, alert_ids";
        }

        @Override
        public String timestampColumn() {
            return "opened_ms";
        }

        @Override
        public String insertSql() {
            return "INSERT OR REPLACE INTO incidents (" + columns() + ") VALUES (?,?,?,?,?,?)";
        }

        @Override
        public void bind(PreparedStatement statement, IncidentRecord row) throws SQLException {
            statement.setString(1, text(row.id()));
            statement.setLong(2, millis(row.openedAt()));
            statement.setString(3, text(row.sourceIp()));
            statement.setString(4, text(row.status()));
            statement.setString(5, text(row.highestSeverity()));
            statement.setString(6, join(row.alertIds()));
        }

        @Override
        public IncidentRecord map(ResultSet rows) throws SQLException {
            return new IncidentRecord(rows.getString("id"), instant(rows.getLong("opened_ms")),
                    rows.getString("source_ip"), rows.getString("status"),
                    rows.getString("highest_severity"), split(rows.getString("alert_ids")));
        }

        @Override
        public long timestamp(IncidentRecord row) {
            return millis(row.openedAt());
        }
    };

    static final TableSpec<ContainmentRecord> CONTAINMENT = new TableSpec<>() {
        @Override
        public String table() {
            return "containment_actions";
        }

        @Override
        public String columns() {
            return "ip, blocked_ms, expires_ms, reason, actor, automatic, released";
        }

        @Override
        public String timestampColumn() {
            return "blocked_ms";
        }

        @Override
        public String insertSql() {
            return "INSERT OR REPLACE INTO containment_actions (" + columns() + ") VALUES (?,?,?,?,?,?,?)";
        }

        @Override
        public void bind(PreparedStatement statement, ContainmentRecord row) throws SQLException {
            statement.setString(1, text(row.ip()));
            statement.setLong(2, millis(row.blockedAt()));
            statement.setLong(3, millis(row.expiresAt()));
            statement.setString(4, text(row.reason()));
            statement.setString(5, text(row.actor()));
            statement.setInt(6, row.automatic() ? 1 : 0);
            statement.setInt(7, row.released() ? 1 : 0);
        }

        @Override
        public ContainmentRecord map(ResultSet rows) throws SQLException {
            return new ContainmentRecord(rows.getString("ip"), instant(rows.getLong("blocked_ms")),
                    instant(rows.getLong("expires_ms")), rows.getString("reason"),
                    rows.getString("actor"), rows.getInt("automatic") == 1, rows.getInt("released") == 1);
        }

        @Override
        public long timestamp(ContainmentRecord row) {
            return millis(row.blockedAt());
        }
    };

    static final TableSpec<AuditRecord> AUDIT = new TableSpec<>() {
        @Override
        public String table() {
            return "audit_entries";
        }

        @Override
        public String columns() {
            return "ts_ms, actor, action, target, outcome, detail";
        }

        @Override
        public String timestampColumn() {
            return "ts_ms";
        }

        @Override
        public String insertSql() {
            return "INSERT INTO audit_entries (ts_ms, actor, action, target, outcome, detail)"
                    + " VALUES (?,?,?,?,?,?)";
        }

        @Override
        public void bind(PreparedStatement statement, AuditRecord row) throws SQLException {
            statement.setLong(1, millis(row.timestamp()));
            statement.setString(2, text(row.actor()));
            statement.setString(3, text(row.action()));
            statement.setString(4, text(row.target()));
            statement.setString(5, text(row.outcome()));
            statement.setString(6, text(row.detail()));
        }

        @Override
        public AuditRecord map(ResultSet rows) throws SQLException {
            return new AuditRecord(instant(rows.getLong("ts_ms")), rows.getString("actor"),
                    rows.getString("action"), rows.getString("target"), rows.getString("outcome"),
                    rows.getString("detail"));
        }

        @Override
        public long timestamp(AuditRecord row) {
            return millis(row.timestamp());
        }
    };

    static final TableSpec<NotificationRecord> NOTIFICATION = new TableSpec<>() {
        @Override
        public String table() {
            return "notifications";
        }

        @Override
        public String columns() {
            return "id, ts_ms, severity, attack_type, source_ip, target_ip, summary, channel";
        }

        @Override
        public String timestampColumn() {
            return "ts_ms";
        }

        @Override
        public String insertSql() {
            return "INSERT OR REPLACE INTO notifications (" + columns() + ") VALUES (?,?,?,?,?,?,?,?)";
        }

        @Override
        public void bind(PreparedStatement statement, NotificationRecord row) throws SQLException {
            statement.setString(1, text(row.id()));
            statement.setLong(2, millis(row.timestamp()));
            statement.setString(3, text(row.severity()));
            statement.setString(4, text(row.attackType()));
            statement.setString(5, text(row.sourceIp()));
            statement.setString(6, text(row.targetIp()));
            statement.setString(7, text(row.summary()));
            statement.setString(8, text(row.channel()));
        }

        @Override
        public NotificationRecord map(ResultSet rows) throws SQLException {
            return new NotificationRecord(rows.getString("id"), instant(rows.getLong("ts_ms")),
                    rows.getString("severity"), rows.getString("attack_type"),
                    rows.getString("source_ip"), rows.getString("target_ip"),
                    rows.getString("summary"), rows.getString("channel"));
        }

        @Override
        public long timestamp(NotificationRecord row) {
            return millis(row.timestamp());
        }
    };

    static final TableSpec<ManifestRecord> MANIFEST = new TableSpec<>() {
        @Override
        public String table() {
            return "evidence_manifests";
        }

        @Override
        public String columns() {
            return "directory, created_ms, files, bytes, manifest_hash";
        }

        @Override
        public String timestampColumn() {
            return "created_ms";
        }

        @Override
        public String insertSql() {
            return "INSERT OR REPLACE INTO evidence_manifests (" + columns() + ") VALUES (?,?,?,?,?)";
        }

        @Override
        public void bind(PreparedStatement statement, ManifestRecord row) throws SQLException {
            statement.setString(1, text(row.directory()));
            statement.setLong(2, millis(row.createdAt()));
            statement.setInt(3, row.files());
            statement.setLong(4, row.bytes());
            statement.setString(5, text(row.manifestHash()));
        }

        @Override
        public ManifestRecord map(ResultSet rows) throws SQLException {
            return new ManifestRecord(rows.getString("directory"), instant(rows.getLong("created_ms")),
                    rows.getInt("files"), rows.getLong("bytes"), rows.getString("manifest_hash"));
        }

        @Override
        public long timestamp(ManifestRecord row) {
            return millis(row.createdAt());
        }
    };

    static final TableSpec<ModelSummaryRecord> MODEL = new TableSpec<>() {
        @Override
        public String table() {
            return "ml_model";
        }

        @Override
        public String columns() {
            return "trained_ms, state, samples, clusters, threshold";
        }

        @Override
        public String timestampColumn() {
            return "trained_ms";
        }

        @Override
        public String insertSql() {
            return "INSERT OR REPLACE INTO ml_model (" + columns() + ") VALUES (?,?,?,?,?)";
        }

        @Override
        public void bind(PreparedStatement statement, ModelSummaryRecord row) throws SQLException {
            statement.setLong(1, millis(row.trainedAt()));
            statement.setString(2, text(row.state()));
            statement.setInt(3, row.samples());
            statement.setInt(4, row.clusters());
            statement.setDouble(5, row.threshold());
        }

        @Override
        public ModelSummaryRecord map(ResultSet rows) throws SQLException {
            return new ModelSummaryRecord(instant(rows.getLong("trained_ms")), rows.getString("state"),
                    rows.getInt("samples"), rows.getInt("clusters"), rows.getDouble("threshold"));
        }

        @Override
        public long timestamp(ModelSummaryRecord row) {
            return millis(row.trainedAt());
        }
    };

    private TableSpecs() {
    }

    private static String text(String value) {
        return value == null ? "" : value;
    }

    private static long millis(Instant value) {
        return value == null ? 0L : value.toEpochMilli();
    }

    private static Instant instant(long value) {
        return value == 0L ? null : Instant.ofEpochMilli(value);
    }

    private static String join(List<String> values) {
        return values == null || values.isEmpty() ? "" : String.join(",", values);
    }

    private static List<String> flags(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split(",")).map(String::trim).filter(item -> !item.isEmpty()).toList();
    }

    private static List<String> split(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        List<String> parts = new ArrayList<>();
        Arrays.stream(raw.split(",")).map(String::trim).filter(item -> !item.isEmpty())
                .forEach(parts::add);
        return List.copyOf(parts);
    }
}
