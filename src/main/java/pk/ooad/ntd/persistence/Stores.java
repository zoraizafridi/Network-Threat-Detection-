package pk.ooad.ntd.persistence;

final class Stores {

    final RecordStore<IncidentRecord> incidents;
    final RecordStore<ContainmentRecord> containment;
    final RecordStore<AuditRecord> audit;
    final RecordStore<NotificationRecord> notifications;
    final RecordStore<ManifestRecord> manifests;
    final RecordStore<ModelSummaryRecord> models;

    private Stores(RecordStore<IncidentRecord> incidents, RecordStore<ContainmentRecord> containment,
                   RecordStore<AuditRecord> audit, RecordStore<NotificationRecord> notifications,
                   RecordStore<ManifestRecord> manifests, RecordStore<ModelSummaryRecord> models) {
        this.incidents = incidents;
        this.containment = containment;
        this.audit = audit;
        this.notifications = notifications;
        this.manifests = manifests;
        this.models = models;
    }

    static Stores sqlite(Database database) {
        return new Stores(
                new SqliteTable<>(database, TableSpecs.INCIDENT),
                new SqliteTable<>(database, TableSpecs.CONTAINMENT),
                new SqliteTable<>(database, TableSpecs.AUDIT),
                new SqliteTable<>(database, TableSpecs.NOTIFICATION),
                new SqliteTable<>(database, TableSpecs.MANIFEST),
                new SqliteTable<>(database, TableSpecs.MODEL));
    }

    static Stores memory(int maxRows) {
        return new Stores(
                new InMemoryRecordStore<>(maxRows, TableSpecs.INCIDENT::timestamp),
                new InMemoryRecordStore<>(maxRows, TableSpecs.CONTAINMENT::timestamp),
                new InMemoryRecordStore<>(maxRows, TableSpecs.AUDIT::timestamp),
                new InMemoryRecordStore<>(maxRows, TableSpecs.NOTIFICATION::timestamp),
                new InMemoryRecordStore<>(maxRows, TableSpecs.MANIFEST::timestamp),
                new InMemoryRecordStore<>(maxRows, TableSpecs.MODEL::timestamp));
    }
}
