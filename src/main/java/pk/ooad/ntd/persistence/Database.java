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

/**
 * Owns the SQLite file: the schema, one write connection and one read
 * connection.
 *
 * <p>Two connections are opened on purpose. SQLite in write-ahead logging mode
 * allows many readers alongside a single writer, so the HTTP threads never wait
 * behind the write-behind batch. The rule that keeps this safe is simple: the
 * write connection is touched only by the persistence worker thread, and the
 * read connection is touched only through the synchronised repository readers.</p>
 *
 * <p>The schema carries a {@code user_version} so a later phase can migrate an
 * existing file instead of silently mismatching it.</p>
 */
final class Database implements AutoCloseable {

    static final int SCHEMA_VERSION = 1;

    static {
        // Loading the driver explicitly keeps the shaded jar honest: relying on
        // ServiceLoader alone would break if the service file is ever filtered.
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
        writer = DriverManager.getConnection(url);
        reader = DriverManager.getConnection(url);
        configure(writer);
        configure(reader);
        migrate();
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

    /** Reads {@code PRAGMA user_version}, used by the tests to prove migration ran. */
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
            // WAL lets the reader run while a batch commits; NORMAL keeps the
            // write cost low because losing the last batch on a power cut is an
            // acceptable trade for a monitoring tool.
            statement.execute("PRAGMA journal_mode=WAL");
            statement.execute("PRAGMA synchronous=NORMAL");
            statement.execute("PRAGMA busy_timeout=5000");
        }
    }

    private void migrate() throws SQLException {
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
            try (PreparedStatement version = writer.prepareStatement("PRAGMA user_version = " + SCHEMA_VERSION)) {
                version.execute();
            }
        }
    }

    private static void closeQuietly(Connection connection) {
        try {
            connection.close();
        } catch (SQLException ignored) {
            // Closing is best effort: the process is on its way down anyway.
        }
    }
}
