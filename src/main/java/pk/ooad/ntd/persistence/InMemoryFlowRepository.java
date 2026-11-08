package pk.ooad.ntd.persistence;

import pk.ooad.ntd.flows.FlowRecord;

final class InMemoryFlowRepository extends InMemoryRecordStore<FlowRecord> implements FlowRepository {

    InMemoryFlowRepository(int maxRows) {
        super(maxRows, row -> row.startTime() == null ? 0L : row.startTime().toEpochMilli());
    }
}
