package pk.ooad.ntd.persistence;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

class SqliteTable<T> implements RecordStore<T> {

    private final Database database;
    private final TableSpec<T> spec;

    SqliteTable(Database database, TableSpec<T> spec) {
        this.database = database;
        this.spec = spec;
    }

    @Override
    public void insertBatch(List<T> batch) throws SQLException {
        if (batch == null || batch.isEmpty()) {
            return;
        }
        Connection connection = database.writer();
        synchronized (connection) {
            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try (PreparedStatement statement = connection.prepareStatement(spec.insertSql())) {
                for (T row : batch) {
                    spec.bind(statement, row);
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

    @Override
    public List<T> recent(int limit) throws SQLException {
        Connection connection = database.reader();
        synchronized (connection) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT " + spec.columns() + " FROM " + spec.table()
                            + " ORDER BY " + spec.timestampColumn() + " DESC, rowid DESC LIMIT ?")) {
                statement.setInt(1, Math.max(1, limit));
                try (ResultSet rows = statement.executeQuery()) {
                    List<T> records = new ArrayList<>();
                    while (rows.next()) {
                        records.add(spec.map(rows));
                    }
                    return records;
                }
            }
        }
    }

    @Override
    public int count() throws SQLException {
        Connection connection = database.reader();
        synchronized (connection) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT COUNT(*) FROM " + spec.table());
                 ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getInt(1) : 0;
            }
        }
    }

    @Override
    public int deleteBefore(Instant cutoff) throws SQLException {
        if (cutoff == null) {
            return 0;
        }
        Connection connection = database.writer();
        synchronized (connection) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM " + spec.table() + " WHERE " + spec.timestampColumn() + " < ?")) {
                statement.setLong(1, cutoff.toEpochMilli());
                return statement.executeUpdate();
            }
        }
    }
}
