package pk.ooad.ntd.persistence;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

interface TableSpec<T> {

    String table();

    String columns();

    String timestampColumn();

    String insertSql();

    void bind(PreparedStatement statement, T row) throws SQLException;

    T map(ResultSet rows) throws SQLException;

    long timestamp(T row);
}
