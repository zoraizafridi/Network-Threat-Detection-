package pk.ooad.ntd.persistence;

final class InMemoryAlertRepository extends InMemoryRecordStore<AlertRecord> implements AlertRepository {

    InMemoryAlertRepository(int maxRows) {
        super(maxRows, row -> row.timestamp() == null ? 0L : row.timestamp().toEpochMilli());
    }
}
