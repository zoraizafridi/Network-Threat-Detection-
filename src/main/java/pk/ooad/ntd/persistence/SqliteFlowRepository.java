package pk.ooad.ntd.persistence;

import pk.ooad.ntd.flows.FlowRecord;

final class SqliteFlowRepository extends SqliteTable<FlowRecord> implements FlowRepository {

    SqliteFlowRepository(Database database) {
        super(database, TableSpecs.FLOW);
    }
}
