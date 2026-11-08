package pk.ooad.ntd.persistence;

import java.sql.SQLException;
import java.time.Instant;
import java.util.List;

public interface RecordStore<T> {

    void insertBatch(List<T> batch) throws SQLException;

    List<T> recent(int limit) throws SQLException;

    int count() throws SQLException;

    int deleteBefore(Instant cutoff) throws SQLException;
}
