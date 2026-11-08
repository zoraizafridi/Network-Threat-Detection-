package pk.ooad.ntd.persistence;

public record PersistenceStatus(
        boolean enabled,
        String databasePath,
        int flowRows,
        int alertRows,
        long queuedFlows,
        long queuedAlerts,
        long droppedRows,
        long writtenRows,
        String lastFlushAt,
        String lastError) {

    public static PersistenceStatus off(String databasePath) {
        return new PersistenceStatus(false, databasePath, 0, 0, 0, 0, 0, 0, null, null);
    }
}
