package pk.ooad.ntd.persistence;

final class SqliteAlertRepository extends SqliteTable<AlertRecord> implements AlertRepository {

    SqliteAlertRepository(Database database) {
        super(database, TableSpecs.ALERT);
    }
}
