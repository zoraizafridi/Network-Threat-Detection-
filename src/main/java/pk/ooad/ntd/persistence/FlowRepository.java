package pk.ooad.ntd.persistence;

import pk.ooad.ntd.flows.FlowRecord;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Reads and writes the {@code flows} table. */
final class FlowRepository {

    private static final String COLUMNS =
            "id, src_ip, dst_ip, src_port, dst_port, protocol, bytes_out, bytes_in, packets, "
                    + "start_ms, end_ms, flags, label, simulated, ended";
    private static final int PARAMETERS = 15;

    private final Database database;

    FlowRepository(Database database) {
        this.database = database;
    }

    void insertBatch(List<FlowRecord> batch) throws SQLException {
        if (batch.isEmpty()) {
            return;
        }
        Connection connection = database.writer();
        synchronized (connection) {
            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT OR REPLACE INTO flows (" + COLUMNS + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")) {
                for (FlowRecord record : batch) {
                    bind(statement, record);
                    statement.addBatch();
                }
                statement.executeBatch();
                connection.commit();
            } catch (SQLException ex) {
                connection.rollback();
                throw ex;
            } finally {
                connection.setAutoCommit(previousAutoCommit);
            }
        }
    }

    List<FlowRecord> recent(int limit) throws SQLException {
        Connection connection = database.reader();
        synchronized (connection) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT " + COLUMNS + " FROM flows ORDER BY start_ms DESC, id DESC LIMIT ?")) {
                statement.setInt(1, Math.max(1, limit));
                try (ResultSet rows = statement.executeQuery()) {
                    List<FlowRecord> records = new ArrayList<>();
                    while (rows.next()) {
                        records.add(map(rows));
                    }
                    return records;
                }
            }
        }
    }

    int deleteBefore(Instant cutoff) throws SQLException {
        if (cutoff == null) {
            return 0;
        }
        Connection connection = database.writer();
        synchronized (connection) {
            try (PreparedStatement statement = connection.prepareStatement("DELETE FROM flows WHERE end_ms < ?")) {
                statement.setLong(1, cutoff.toEpochMilli());
                return statement.executeUpdate();
            }
        }
    }

    int count() throws SQLException {
        Connection connection = database.reader();
        synchronized (connection) {
            try (PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM flows");
                 ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getInt(1) : 0;
            }
        }
    }

    private static void bind(PreparedStatement statement, FlowRecord record) throws SQLException {
        int index = 1;
        statement.setString(index++, record.id());
        statement.setString(index++, record.srcIp());
        statement.setString(index++, record.dstIp());
        statement.setInt(index++, record.srcPort());
        statement.setInt(index++, record.dstPort());
        statement.setString(index++, record.protocol());
        statement.setLong(index++, record.bytesOut());
        statement.setLong(index++, record.bytesIn());
        statement.setLong(index++, record.packets());
        statement.setLong(index++, millis(record.startTime()));
        statement.setLong(index++, millis(record.endTime()));
        statement.setString(index++, String.join(",", record.flags()));
        statement.setString(index++, record.label());
        statement.setInt(index++, record.simulated() ? 1 : 0);
        statement.setInt(index++, record.ended() ? 1 : 0);
        // Guard: the parameter count above and PARAMETERS must stay in step.
        if (index != PARAMETERS + 1) {
            throw new SQLException("Flow binding wrote " + (index - 1) + " of " + PARAMETERS + " parameters");
        }
    }

    private static FlowRecord map(ResultSet rows) throws SQLException {
        return new FlowRecord(
                rows.getString("id"),
                rows.getString("src_ip"),
                rows.getString("dst_ip"),
                rows.getInt("src_port"),
                rows.getInt("dst_port"),
                rows.getString("protocol"),
                rows.getLong("bytes_out"),
                rows.getLong("bytes_in"),
                rows.getLong("packets"),
                instant(rows.getLong("start_ms")),
                instant(rows.getLong("end_ms")),
                flags(rows.getString("flags")),
                rows.getString("label"),
                rows.getInt("simulated") == 1,
                rows.getInt("ended") == 1);
    }

    private static long millis(Instant value) {
        return value == null ? 0L : value.toEpochMilli();
    }

    private static Instant instant(long value) {
        return value == 0L ? null : Instant.ofEpochMilli(value);
    }

    private static List<String> flags(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(item -> !item.isEmpty())
                .toList();
    }
}
