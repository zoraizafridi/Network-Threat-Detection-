package pk.ooad.ntd.persistence;

/** Raised when the durable store cannot be read or written. */
public class PersistenceException extends RuntimeException {

    public PersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}
