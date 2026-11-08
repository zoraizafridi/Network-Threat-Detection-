package pk.ooad.ntd.persistence;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.ToLongFunction;

class InMemoryRecordStore<T> implements RecordStore<T> {

    private final int maxRows;
    private final ToLongFunction<T> clock;
    private final List<T> rows = new ArrayList<>();

    InMemoryRecordStore(int maxRows, ToLongFunction<T> clock) {
        this.maxRows = Math.max(1, maxRows);
        this.clock = clock;
    }

    @Override
    public synchronized void insertBatch(List<T> batch) {
        if (batch == null || batch.isEmpty()) {
            return;
        }
        rows.addAll(batch);
        while (rows.size() > maxRows) {
            rows.remove(0);
        }
    }

    @Override
    public synchronized List<T> recent(int limit) {
        int count = Math.min(Math.max(limit, 0), rows.size());
        List<T> sorted = new ArrayList<>(rows);
        sorted.sort(Comparator.comparingLong(clock).reversed());
        return new ArrayList<>(sorted.subList(0, count));
    }

    @Override
    public synchronized int count() {
        return rows.size();
    }

    @Override
    public synchronized int deleteBefore(Instant cutoff) {
        if (cutoff == null) {
            return 0;
        }
        long limit = cutoff.toEpochMilli();
        int before = rows.size();
        rows.removeIf(row -> clock.applyAsLong(row) < limit);
        return before - rows.size();
    }
}
