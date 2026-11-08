package pk.ooad.ntd.persistence;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Reads and writes the {@code alerts} table. */
final class AlertRepository {

    private static final String COLUMNS =
            "id, ts_ms, severity, attack_type, source_ip, target_ip, detector, description, simulated";

    private final Database database;

    AlertRepository(Database database) {
        this.database = database;
    }

    void insertBatch(List<AlertRecord> batch) throws SQLException {
        if (batch.isEmpty()) {
            return;
        }
        Connection connection = database.writer();
        synchronized (connection) {
            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT OR REPLACE INTO alerts (" + COLUMNS + ") VALUES (?,?,?,?,?,?,?,?,?)")) {
                for (AlertRecord record : batch) {
                    int index = 1;
                    statement.setString(index++, record.id());
                    statement.setLong(index++, record.timestamp() == null ? 0L : record.timestamp().toEpochMilli());
                    statement.setString(index++, nullToEmpty(record.severity()));
                    statement.setString(index++, nullToEmpty(record.attackType()));
                    statement.setString(index++, nullToEmpty(record.sourceIp()));
                    statement.setString(index++, nullToEmpty(record.targetIp()));
                    statement.setString(index++, nullToEmpty(record.detector()));
                    statement.setString(index++, nullToEmpty(record.description()));
                    statement.setInt(index++, record.simulated() ? 1 : 0);
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

    List<AlertRecord> recent(int limit) throws SQLException {
        Connection connection = database.reader();
        synchronized (connection) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT " + COLUMNS + " FROM alerts ORDER BY ts_ms DESC, id DESC LIMIT ?")) {
                statement.setInt(1, Math.max(1, limit));
                try (ResultSet rows = statement.executeQuery()) {
                    List<AlertRecord> records = new ArrayList<>();
                    while (rows.next()) {
                        records.add(new AlertRecord(
                                rows.getString("id"),
                                rows.getLong("ts_ms") == 0L ? null : Instant.ofEpochMilli(rows.getLong("ts_ms")),
                                rows.getString("severity"),
                                rows.getString("attack_type"),
                                rows.getString("source_ip"),
                                rows.getString("target_ip"),
                                rows.getString("detector"),
                                rows.getString("description"),
                                rows.getInt("simulated") == 1));
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
            try (PreparedStatement statement = connection.prepareStatement("DELETE FROM alerts WHERE ts_ms < ?")) {
                statement.setLong(1, cutoff.toEpochMilli());
                return statement.executeUpdate();
            }
        }
    }

    int count() throws SQLException {
        Connection connection = database.reader();
        synchronized (connection) {
            try (PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM alerts");
                 ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getInt(1) : 0;
            }
        }
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
