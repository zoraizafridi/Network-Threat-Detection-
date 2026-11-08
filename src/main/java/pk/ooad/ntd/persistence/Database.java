package pk.ooad.ntd.persistence;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

final class Database implements AutoCloseable {

    static final int SCHEMA_VERSION = 2;

    static {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException ex) {
            throw new IllegalStateException("SQLite JDBC driver is not on the classpath", ex);
        }
    }

    private final Connection writer;
    private final Connection reader;
    private final Path file;

    Database(Path file) throws SQLException {
        this.file = file.toAbsolutePath();
        Path parent = this.file.getParent();
        if (parent != null) {
            try {
                Files.createDirectories(parent);
            } catch (IOException ex) {
                throw new SQLException("Cannot create the database directory " + parent, ex);
            }
        }
        String url = "jdbc:sqlite:" + this.file;
        Connection openedWriter = null;
        Connection openedReader = null;
        try {
            openedWriter = DriverManager.getConnection(url);
            openedReader = DriverManager.getConnection(url);
            configure(openedWriter);
            configure(openedReader);
            this.writer = openedWriter;
            this.reader = openedReader;
            migrate();
        } catch (SQLException | RuntimeException ex) {
            closeQuietly(openedReader);
            closeQuietly(openedWriter);
            throw ex;
        }
    }

    Connection writer() {
        return writer;
    }

    Connection reader() {
        return reader;
    }

    Path file() {
        return file;
    }

    int schemaVersion() throws SQLException {
        synchronized (reader) {
            try (Statement statement = reader.createStatement();
                 ResultSet rows = statement.executeQuery("PRAGMA user_version")) {
                return rows.next() ? rows.getInt(1) : -1;
            }
        }
    }

    @Override
    public void close() {
        closeQuietly(reader);
        closeQuietly(writer);
    }

    private static void configure(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA journal_mode=WAL");
            statement.execute("PRAGMA synchronous=NORMAL");
            statement.execute("PRAGMA busy_timeout=5000");
        }
    }

    private void migrate() throws SQLException {
        int current = readVersion();
        if (current > SCHEMA_VERSION) {
            throw new SQLException("The database at " + file + " was written by a newer build (schema "
                    + current + ", this build understands " + SCHEMA_VERSION + ")");
        }
        if (current < 1) {
            applyV1();
        }
        if (current < 2) {
            applyV2();
        }
        writeVersion(SCHEMA_VERSION);
    }

    private void applyV1() throws SQLException {
        try (Statement statement = writer.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS flows (
                        id          TEXT PRIMARY KEY,
                        src_ip      TEXT    NOT NULL,
                        dst_ip      TEXT    NOT NULL,
                        src_port    INTEGER NOT NULL,
                        dst_port    INTEGER NOT NULL,
                        protocol    TEXT    NOT NULL,
                        bytes_out   INTEGER NOT NULL,
                        bytes_in    INTEGER NOT NULL,
                        packets     INTEGER NOT NULL,
                        start_ms    INTEGER NOT NULL,
                        end_ms      INTEGER NOT NULL,
                        flags       TEXT    NOT NULL,
                        label       TEXT    NOT NULL,
                        simulated   INTEGER NOT NULL,
                        ended       INTEGER NOT NULL
                    )
                    """);
            statement.execute("CREATE INDEX IF NOT EXISTS flows_start ON flows(start_ms DESC)");
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id          TEXT PRIMARY KEY,
                        ts_ms       INTEGER NOT NULL,
                        severity    TEXT    NOT NULL,
                        attack_type TEXT    NOT NULL,
                        source_ip   TEXT    NOT NULL,
                        target_ip   TEXT    NOT NULL,
                        detector    TEXT    NOT NULL,
                        description TEXT    NOT NULL,
                        simulated   INTEGER NOT NULL
                    )
                    """);
            statement.execute("CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts_ms DESC)");
        }
    }

    private void applyV2() throws SQLException {
        try (Statement statement = writer.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS incidents (
                        id               TEXT PRIMARY KEY,
                        opened_ms        INTEGER NOT NULL,
                        source_ip        TEXT    NOT NULL,
                        status           TEXT    NOT NULL,
                        highest_severity TEXT    NOT NULL,
                        alert_ids        TEXT    NOT NULL
                    )
                    """);
            statement.execute("CREATE INDEX IF NOT EXISTS incidents_opened ON incidents(opened_ms DESC)");
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS containment_actions (
                        ip         TEXT PRIMARY KEY,
                        blocked_ms INTEGER NOT NULL,
                        expires_ms INTEGER NOT NULL,
                        reason     TEXT    NOT NULL,
                        actor      TEXT    NOT NULL,
                        automatic  INTEGER NOT NULL,
                        released   INTEGER NOT NULL
                    )
                    """);
            statement.execute("CREATE INDEX IF NOT EXISTS containment_blocked"
                    + " ON containment_actions(blocked_ms DESC)");
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS audit_entries (
                        ts_ms   INTEGER NOT NULL,
                        actor   TEXT    NOT NULL,
                        action  TEXT    NOT NULL,
                        target  TEXT    NOT NULL,
                        outcome TEXT    NOT NULL,
                        detail  TEXT    NOT NULL
                    )
                    """);
            statement.execute("CREATE INDEX IF NOT EXISTS audit_ts ON audit_entries(ts_ms DESC)");
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS notifications (
                        id          TEXT PRIMARY KEY,
                        ts_ms       INTEGER NOT NULL,
                        severity    TEXT    NOT NULL,
                        attack_type TEXT    NOT NULL,
                        source_ip   TEXT    NOT NULL,
                        target_ip   TEXT    NOT NULL,
                        summary     TEXT    NOT NULL,
                        channel     TEXT    NOT NULL
                    )
                    """);
            statement.execute("CREATE INDEX IF NOT EXISTS notifications_ts ON notifications(ts_ms DESC)");
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS evidence_manifests (
                        directory     TEXT PRIMARY KEY,
                        created_ms    INTEGER NOT NULL,
                        files         INTEGER NOT NULL,
                        bytes         INTEGER NOT NULL,
                        manifest_hash TEXT    NOT NULL
                    )
                    """);
            statement.execute("CREATE INDEX IF NOT EXISTS evidence_created"
                    + " ON evidence_manifests(created_ms DESC)");
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS ml_model (
                        id         INTEGER PRIMARY KEY CHECK (id = 1),
                        trained_ms INTEGER NOT NULL,
                        state      TEXT    NOT NULL,
                        samples    INTEGER NOT NULL,
                        clusters   INTEGER NOT NULL,
                        threshold  REAL    NOT NULL
                    )
                    """);
            addColumn(statement, "alerts", "occurrences", "INTEGER NOT NULL DEFAULT 1");
            addColumn(statement, "alerts", "first_seen_ms", "INTEGER NOT NULL DEFAULT 0");
            addColumn(statement, "alerts", "last_seen_ms", "INTEGER NOT NULL DEFAULT 0");
            addColumn(statement, "alerts", "status", "TEXT NOT NULL DEFAULT 'NEW'");
        }
    }

    private void addColumn(Statement statement, String table, String column, String definition)
            throws SQLException {
        if (hasColumn(statement, table, column)) {
            return;
        }
        statement.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition);
    }

    private static boolean hasColumn(Statement statement, String table, String column) throws SQLException {
        try (ResultSet rows = statement.executeQuery("PRAGMA table_info(" + table + ")")) {
            while (rows.next()) {
                if (column.equalsIgnoreCase(rows.getString("name"))) {
                    return true;
                }
            }
            return false;
        }
    }

    private int readVersion() throws SQLException {
        try (Statement statement = writer.createStatement();
             ResultSet rows = statement.executeQuery("PRAGMA user_version")) {
            return rows.next() ? rows.getInt(1) : 0;
        }
    }

    private void writeVersion(int version) throws SQLException {
        try (PreparedStatement statement = writer.prepareStatement("PRAGMA user_version = " + version)) {
            statement.execute();
        }
    }

    private static void closeQuietly(Connection connection) {
        try {
            connection.close();
        } catch (SQLException ignored) {
        }
    }
}
