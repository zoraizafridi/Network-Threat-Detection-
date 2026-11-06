package pk.ooad.ntd.util;

public class InvalidConfigException extends RuntimeException {
    public InvalidConfigException(String message) {
        super(message);
    }

    public InvalidConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
