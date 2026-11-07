package pk.ooad.ntd.web;

import pk.ooad.ntd.util.ConfigManager;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding window failure counter used to slow down credential stuffing
 * without locking out an account permanently.
 */
final class LoginThrottle {
    private static final class Window {
        private long start;
        private int failures;
    }

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final int maxAttempts;
    private final int windowSeconds;
    private final long windowNanos;

    LoginThrottle() {
        this(
                ConfigManager.getInstance().getInt("auth.login.maxAttempts", 5),
                ConfigManager.getInstance().getInt("auth.login.windowSeconds", 300));
    }

    LoginThrottle(int maxAttempts, int windowSeconds) {
        this.maxAttempts = Math.max(1, maxAttempts);
        this.windowSeconds = Math.max(1, windowSeconds);
        this.windowNanos = this.windowSeconds * 1_000_000_000L;
    }

    boolean allowed(String key) {
        Window window = windows.get(key);
        if (window == null) {
            return true;
        }
        synchronized (window) {
            if (System.nanoTime() - window.start >= windowNanos) {
                windows.remove(key);
                return true;
            }
            return window.failures < maxAttempts;
        }
    }

    int retryAfterSeconds(String key) {
        Window window = windows.get(key);
        if (window == null) {
            return 0;
        }
        synchronized (window) {
            long remaining = windowNanos - (System.nanoTime() - window.start);
            return (int) Math.max(1L, (remaining + 999_999_999L) / 1_000_000_000L);
        }
    }

    void recordFailure(String key) {
        long now = System.nanoTime();
        windows.compute(key, (ignored, current) -> {
            if (current == null || now - current.start >= windowNanos) {
                Window fresh = new Window();
                fresh.start = now;
                fresh.failures = 1;
                return fresh;
            }
            current.failures++;
            return current;
        });
    }

    void clear(String key) {
        windows.remove(key);
    }

    int getMaxAttempts() {
        return maxAttempts;
    }

    int getWindowSeconds() {
        return windowSeconds;
    }
}
