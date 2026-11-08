package pk.ooad.ntd.notify;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Turns alerts nobody is watching a dashboard for into something a person can
 * receive: an entry in a bounded outbox the UI reads, and optionally a webhook.
 *
 * <p>Delivery is asynchronous and bounded. An alert is recorded before the
 * webhook is attempted, so a slow receiver loses freshness but never loses the
 * row; the in-flight counter drops attempts beyond the limit rather than
 * letting a broken endpoint turn into unbounded threads. Failures are counted
 * and surfaced in the status instead of being swallowed by a background
 * callback.</p>
 */
public final class NotificationService implements AlertListener {

    public record Notification(String id, Instant timestamp, Severity severity, String attackType,
                               String sourceIp, String targetIp, String summary, String channel) {
    }

    public record Status(boolean enabled, String minimumSeverity, boolean webhookConfigured,
                         int outboxSize, int maxOutbox, long recorded, long webhookSent,
                         long webhookFailed, long dropped, String lastError) {
    }

    private final boolean enabled;
    private final Severity minimumSeverity;
    private final int maxOutbox;
    private final String webhookUrl;
    private final int maxInFlight;
    private final Deque<Notification> outbox = new ArrayDeque<>();
    private final AtomicLong recorded = new AtomicLong();
    private final AtomicLong webhookSent = new AtomicLong();
    private final AtomicLong webhookFailed = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicInteger inFlight = new AtomicInteger();
    private volatile String lastError;
    private volatile HttpClient client;

    public NotificationService() {
        this(ConfigManager.getInstance());
    }

    public NotificationService(ConfigManager config) {
        this(Boolean.parseBoolean(config.getString("notifications.enabled", "false")),
                severity(config.getString("notifications.minSeverity", "HIGH")),
                config.getInt("notifications.maxOutbox", 200),
                config.getString("notifications.webhook.url", ""),
                config.getInt("notifications.maxInFlight", 8),
                config.getInt("notifications.webhook.timeoutMillis", 2000));
    }

    NotificationService(boolean enabled, Severity minimumSeverity, int maxOutbox, String webhookUrl,
                        int maxInFlight, int timeoutMillis) {
        this.enabled = enabled;
        this.minimumSeverity = minimumSeverity == null ? Severity.HIGH : minimumSeverity;
        this.maxOutbox = Math.max(1, maxOutbox);
        this.webhookUrl = webhookUrl == null ? "" : webhookUrl.trim();
        this.maxInFlight = Math.max(1, maxInFlight);
        if (enabled && !this.webhookUrl.isEmpty()) {
            client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(Math.max(100, timeoutMillis)))
                    .build();
        }
    }

    @Override
    public void onAlert(Alert alert) {
        if (!enabled || alert == null || alert.getSeverity().compareTo(minimumSeverity) < 0) {
            return;
        }
        Notification notification = new Notification(
                alert.getId(),
                alert.getTimestamp() == null ? Instant.now() : alert.getTimestamp(),
                alert.getSeverity(),
                alert.getAttackType().name(),
                alert.getSourceIp(),
                alert.getTargetIp(),
                alert.getDetectorName() + ": " + alert.getDescription(),
                client == null ? "outbox" : "outbox+webhook");
        synchronized (this) {
            if (outbox.size() >= maxOutbox) {
                outbox.removeFirst();
                dropped.incrementAndGet();
            }
            outbox.addLast(notification);
        }
        recorded.incrementAndGet();
        EventLog.getInstance().log(LogLevel.WARN, "notify",
                alert.getSeverity() + " " + alert.getAttackType() + " from " + alert.getSourceIp());
        if (client != null) {
            send(notification);
        }
    }

    public synchronized List<Notification> recent(int limit) {
        int bounded = Math.max(0, Math.min(limit, maxOutbox));
        List<Notification> rows = new ArrayList<>();
        var iterator = outbox.descendingIterator();
        while (iterator.hasNext() && rows.size() < bounded) {
            rows.add(iterator.next());
        }
        return rows;
    }

    public Status status() {
        return new Status(enabled, minimumSeverity.name(), client != null,
                size(), maxOutbox, recorded.get(), webhookSent.get(), webhookFailed.get(),
                dropped.get(), lastError == null ? "" : lastError);
    }

    public synchronized void reset() {
        outbox.clear();
        recorded.set(0);
        webhookSent.set(0);
        webhookFailed.set(0);
        dropped.set(0);
        lastError = null;
    }

    private synchronized int size() {
        return outbox.size();
    }

    private void send(Notification notification) {
        if (inFlight.incrementAndGet() > maxInFlight) {
            inFlight.decrementAndGet();
            webhookFailed.incrementAndGet();
            lastError = "webhook in-flight limit reached";
            return;
        }
        String payload = json(notification);
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(webhookUrl))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                    .build();
            client.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .whenComplete((response, error) -> {
                        inFlight.decrementAndGet();
                        if (error != null) {
                            webhookFailed.incrementAndGet();
                            lastError = error.getClass().getSimpleName() + ": " + error.getMessage();
                        } else if (response.statusCode() >= 400) {
                            webhookFailed.incrementAndGet();
                            lastError = "webhook answered " + response.statusCode();
                        } else {
                            webhookSent.incrementAndGet();
                        }
                    });
        } catch (RuntimeException ex) {
            inFlight.decrementAndGet();
            webhookFailed.incrementAndGet();
            lastError = ex.getClass().getSimpleName() + ": " + ex.getMessage();
        }
    }

    private static String json(Notification notification) {
        return "{\"id\":\"" + escape(notification.id())
                + "\",\"timestamp\":\"" + notification.timestamp()
                + "\",\"severity\":\"" + notification.severity()
                + "\",\"attackType\":\"" + notification.attackType()
                + "\",\"sourceIp\":\"" + escape(notification.sourceIp())
                + "\",\"targetIp\":\"" + escape(notification.targetIp())
                + "\",\"summary\":\"" + escape(notification.summary()) + "\"}";
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    private static Severity severity(String raw) {
        if (raw == null) {
            return Severity.HIGH;
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return Severity.HIGH;
        }
    }
}
