package pk.ooad.ntd.persistence;

/**
 * What the durable store is doing, as the operator sees it.
 *
 * <p>{@code droppedRows} is the honest part of this record: a full queue or a
 * failing disk loses rows, and the count is reported instead of hidden.</p>
 */
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
