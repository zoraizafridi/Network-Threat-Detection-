package pk.ooad.ntd.notify;

import pk.ooad.ntd.correlation.SiemCorrelator;
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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class NotificationService implements AlertListener {

    public record Notification(String id, Instant timestamp, Severity severity, String attackType,
                               String sourceIp, String targetIp, String summary, String channel,
                               boolean escalation) {
    }

    public record Status(boolean enabled, String minimumSeverity, boolean webhookConfigured,
                         int outboxSize, int maxOutbox, long recorded, long webhookSent,
                         long webhookFailed, long dropped, String lastError) {
    }

    public record Delivery(Instant at, String channel, String outcome, int attempts, String detail) {
    }

    public record Settings(boolean enabled, Severity minimumSeverity, int maxOutbox, String webhookUrl,
                           boolean console, boolean email, String emailRecipient, int maxInFlight,
                           int timeoutMillis, boolean allowInsecure, int retries, long backoffMillis,
                           int breakerThreshold, int breakerCooldownSeconds, int maxPerHour,
                           int cooldownSeconds, int maxBodyBytes, int historyMax, boolean redact) {
    }

    public record Health(boolean enabled, boolean console, boolean email, String emailRecipient,
                         String webhookHost, String webhookRefusal, boolean breakerOpen,
                         int consecutiveFailures, String breakerUntil, long suppressed,
                         long rateLimited, long cooldownSkipped, long refused,
                         long consoleSent, long emailSent, long emailFailed) {
    }

    public interface Recorder {
        void attempt(String channel, String outcome, String detail);
    }

    private final Settings settings;
    private final Severity minimumSeverity;
    private final int maxOutbox;
    private final String webhookUrl;
    private final int maxInFlight;
    private final int timeoutMillis;
    private final boolean allowInsecure;
    private final int retries;
    private final long backoffMillis;
    private final int breakerThreshold;
    private final int breakerCooldownSeconds;
    private final int maxPerHour;
    private final int cooldownSeconds;
    private final int maxBodyBytes;
    private final int historyMax;
    private final boolean consoleEnabled;
    private final boolean redact;
    private final Mailer mailer;
    private final String secret;
    private final HttpClient client;
    private final String guardRefusal;

    private final Deque<Notification> outbox = new ArrayDeque<>();
    private final Deque<Delivery> history = new ArrayDeque<>();
    private final Deque<Instant> sentWindow = new ArrayDeque<>();
    private final Map<String, Instant> cooldowns = new HashMap<>();
    private final AtomicLong recorded = new AtomicLong();
    private final AtomicLong webhookSent = new AtomicLong();
    private final AtomicLong webhookFailed = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong suppressed = new AtomicLong();
    private final AtomicLong rateLimited = new AtomicLong();
    private final AtomicLong cooldownSkipped = new AtomicLong();
    private final AtomicLong refused = new AtomicLong();
    private final AtomicLong consoleSent = new AtomicLong();
    private final AtomicLong emailSent = new AtomicLong();
    private final AtomicLong emailFailed = new AtomicLong();
    private final AtomicInteger inFlight = new AtomicInteger();
    private final AtomicInteger consecutiveFailures = new AtomicInteger();
    private volatile boolean enabled;
    private volatile Deadline openUntil;
    private volatile String lastError;
    private volatile Recorder recorder = (channel, outcome, detail) -> { };
    private volatile ExecutorService worker;

    public NotificationService() {
        this(ConfigManager.getInstance());
    }

    public NotificationService(ConfigManager config) {
        this(settings(config), mailer(config), System.getenv("NTD_WEBHOOK_SECRET"));
    }

    NotificationService(boolean enabled, Severity minimumSeverity, int maxOutbox, String webhookUrl,
                        int maxInFlight, int timeoutMillis) {
        this(new Settings(enabled, minimumSeverity, maxOutbox, webhookUrl, false, false, "",
                        maxInFlight, timeoutMillis, true, 0, 0, 0, 0, 0, 0, 0, 50, false),
                null, null);
    }

    public NotificationService(Settings settings, Mailer mailer, String secret) {
        this.settings = settings;
        this.enabled = settings.enabled();
        this.minimumSeverity = settings.minimumSeverity() == null ? Severity.HIGH : settings.minimumSeverity();
        this.maxOutbox = Math.max(1, settings.maxOutbox());
        this.webhookUrl = settings.webhookUrl() == null ? "" : settings.webhookUrl().trim();
        this.maxInFlight = Math.max(1, settings.maxInFlight());
        this.timeoutMillis = Math.max(100, settings.timeoutMillis());
        this.allowInsecure = settings.allowInsecure();
        this.retries = Math.max(0, settings.retries());
        this.backoffMillis = Math.max(0, settings.backoffMillis());
        this.breakerThreshold = Math.max(0, settings.breakerThreshold());
        this.breakerCooldownSeconds = Math.max(1, settings.breakerCooldownSeconds());
        this.maxPerHour = Math.max(0, settings.maxPerHour());
        this.cooldownSeconds = Math.max(0, settings.cooldownSeconds());
        this.maxBodyBytes = Math.max(0, settings.maxBodyBytes());
        this.historyMax = Math.max(0, settings.historyMax());
        this.consoleEnabled = settings.console();
        this.redact = settings.redact();
        this.mailer = mailer;
        this.secret = secret == null ? "" : secret;
        if (enabled && !webhookUrl.isEmpty()) {
            WebhookGuard.Verdict verdict = WebhookGuard.check(webhookUrl, allowInsecure);
            if (verdict.allowed()) {
                this.client = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofMillis(timeoutMillis))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build();
                this.guardRefusal = null;
            } else {
                this.client = null;
                this.guardRefusal = verdict.refusal();
                this.lastError = "webhook refused: " + verdict.refusal();
                EventLog.getInstance().log(LogLevel.WARN, "notify",
                        "webhook url refused: " + verdict.refusal());
            }
        } else {
            this.client = null;
            this.guardRefusal = null;
        }
    }

    @Override
    public void onAlert(Alert alert) {
        if (!enabled || alert == null) {
            return;
        }
        if (alert.getSeverity().compareTo(minimumSeverity) < 0) {
            suppressed.incrementAndGet();
            return;
        }
        boolean escalation = SiemCorrelator.DETECTOR_NAME.equals(alert.getDetectorName());
        Notification notification = new Notification(
                alert.getId(),
                alert.getTimestamp() == null ? Instant.now() : alert.getTimestamp(),
                alert.getSeverity(),
                alert.getAttackType().name(),
                alert.getSourceIp(),
                alert.getTargetIp(),
                clip(sanitize(alert.getDetectorName() + ": " + alert.getDescription())),
                channels(),
                escalation);
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
        if (consoleEnabled) {
            EventLog.getInstance().log(LogLevel.INFO, "notify",
                    "delivered " + notification.severity() + " " + notification.attackType()
                            + " " + notification.summary());
            consoleSent.incrementAndGet();
        }
        if (client != null || guardRefusal != null) {
            dispatchWebhook(notification);
        }
        if (mailer != null) {
            dispatchEmail(notification);
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

    public synchronized List<Delivery> history(int limit) {
        int bounded = Math.max(0, limit);
        List<Delivery> rows = new ArrayList<>();
        var iterator = history.descendingIterator();
        while (iterator.hasNext() && rows.size() < bounded) {
            rows.add(iterator.next());
        }
        return rows;
    }

    public Status status() {
        return new Status(enabled, minimumSeverity.name(), enabled && !webhookUrl.isEmpty(),
                size(), maxOutbox, recorded.get(), webhookSent.get(), webhookFailed.get(),
                dropped.get(), lastError == null ? "" : lastError);
    }

    public Health health() {
        boolean open = breakerOpen();
        return new Health(enabled, consoleEnabled, mailer != null,
                settings.emailRecipient(), host(webhookUrl), guardRefusal == null ? "" : guardRefusal,
                open, consecutiveFailures.get(),
                open && openUntil != null ? openUntil.at().toString() : "",
                suppressed.get(), rateLimited.get(), cooldownSkipped.get(), refused.get(),
                consoleSent.get(), emailSent.get(), emailFailed.get());
    }

    public Settings settings() {
        return settings;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean value) {
        this.enabled = value;
        EventLog.getInstance().log(LogLevel.INFO, "notify", "notifications " + (value ? "enabled" : "disabled"));
    }

    public void setRecorder(Recorder recorder) {
        this.recorder = recorder == null ? (channel, outcome, detail) -> { } : recorder;
    }

    public List<Delivery> test() {
        List<Delivery> results = new ArrayList<>();
        Instant now = Instant.now();
        String summary = clip(sanitize("Notification test from the control room"));
        Notification probe = new Notification("test-" + UUID.randomUUID(), now, Severity.HIGH,
                "TEST", "127.0.0.1", "127.0.0.1", summary, "probe", false);
        if (!enabled) {
            results.add(record("all", "disabled", 0, "notifications are off"));
            return results;
        }
        if (consoleEnabled) {
            EventLog.getInstance().log(LogLevel.INFO, "notify", "test delivery through the console");
            consoleSent.incrementAndGet();
            results.add(record("console", "sent", 1, "event log entry written"));
        } else {
            results.add(record("console", "disabled", 0, "notifications.console is false"));
        }
        if (mailer == null) {
            results.add(record("email", "disabled", 0, "notifications.email.enabled is false or incomplete"));
        } else {
            try {
                mailer.send("[NTD] Notification test", body(probe));
                emailSent.incrementAndGet();
                results.add(record("email", "sent", 1, "relay accepted the message"));
            } catch (Exception ex) {
                emailFailed.incrementAndGet();
                String detail = ex.getClass().getSimpleName() + ": " + ex.getMessage();
                lastError = detail;
                results.add(record("email", "failed", 1, detail));
            }
        }
        if (webhookUrl.isEmpty()) {
            results.add(record("webhook", "disabled", 0, "notifications.webhook.url is empty"));
        } else if (guardRefusal != null) {
            refused.incrementAndGet();
            results.add(record("webhook", "refused", 0, guardRefusal));
        } else {
            String payload = json(probe);
            try {
                HttpResponse<Void> response = client.send(request(payload), HttpResponse.BodyHandlers.discarding());
                if (response.statusCode() >= 400) {
                    webhookFailed.incrementAndGet();
                    lastError = "webhook answered " + response.statusCode();
                    results.add(record("webhook", "failed", 1, lastError));
                } else {
                    webhookSent.incrementAndGet();
                    results.add(record("webhook", "sent", 1, "answered " + response.statusCode()));
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                webhookFailed.incrementAndGet();
                results.add(record("webhook", "failed", 1, "interrupted"));
            } catch (Exception ex) {
                webhookFailed.incrementAndGet();
                lastError = ex.getClass().getSimpleName() + ": " + ex.getMessage();
                results.add(record("webhook", "failed", 1, lastError));
            }
        }
        return results;
    }

    public synchronized void reset() {
        outbox.clear();
        history.clear();
        sentWindow.clear();
        cooldowns.clear();
        recorded.set(0);
        webhookSent.set(0);
        webhookFailed.set(0);
        dropped.set(0);
        suppressed.set(0);
        rateLimited.set(0);
        cooldownSkipped.set(0);
        refused.set(0);
        consoleSent.set(0);
        emailSent.set(0);
        emailFailed.set(0);
        inFlight.set(0);
        consecutiveFailures.set(0);
        openUntil = null;
        lastError = null;
    }

    public synchronized void shutdown() {
        ExecutorService current = worker;
        worker = null;
        if (current != null) {
            current.shutdownNow();
        }
    }

    private void dispatchWebhook(Notification notification) {
        if (guardRefusal != null) {
            refused.incrementAndGet();
            webhookFailed.incrementAndGet();
            lastError = "webhook refused: " + guardRefusal;
            record("webhook", "refused", 0, guardRefusal);
            audit("webhook", "refused", notification.id(), guardRefusal);
            return;
        }
        if (!gate(notification)) {
            return;
        }
        String payload = json(notification);
        submit(() -> attempt(notification, payload));
    }

    private void dispatchEmail(Notification notification) {
        submit(() -> {
            int attempts = 0;
            String failure = null;
            while (attempts <= retries) {
                attempts++;
                try {
                    mailer.send("[NTD] " + notification.severity() + " " + notification.attackType(),
                            body(notification));
                    emailSent.incrementAndGet();
                    record("email", "sent", attempts, "relay accepted the message");
                    audit("email", "sent", notification.id(), "attempts " + attempts);
                    return;
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    failure = "interrupted";
                    break;
                } catch (Exception ex) {
                    failure = ex.getClass().getSimpleName() + ": " + ex.getMessage();
                }
                if (attempts <= retries) {
                    pause(attempts);
                }
            }
            emailFailed.incrementAndGet();
            lastError = failure == null ? "email delivery failed" : failure;
            record("email", "failed", attempts, lastError);
            audit("email", "failed", notification.id(), lastError);
        });
    }

    private synchronized boolean gate(Notification notification) {
        Instant now = Instant.now();
        if (breakerOpen()) {
            return false;
        }
        if (maxPerHour > 0) {
            while (!sentWindow.isEmpty()
                    && sentWindow.peekFirst().isBefore(now.minus(Duration.ofHours(1)))) {
                sentWindow.removeFirst();
            }
            if (sentWindow.size() >= maxPerHour) {
                rateLimited.incrementAndGet();
                lastError = "webhook hourly limit of " + maxPerHour + " reached";
                record("webhook", "skipped", 0, lastError);
                return false;
            }
        }
        if (cooldownSeconds > 0) {
            String key = (notification.sourceIp() == null ? "" : notification.sourceIp()) + "|"
                    + notification.attackType();
            Instant last = cooldowns.get(key);
            if (last != null && now.isBefore(last.plusSeconds(cooldownSeconds))) {
                cooldownSkipped.incrementAndGet();
                record("webhook", "skipped", 0, "cooldown for " + key);
                return false;
            }
            cooldowns.put(key, now);
            if (cooldowns.size() > 512) {
                cooldowns.values().removeIf(at -> at.isBefore(now.minusSeconds(cooldownSeconds)));
            }
        }
        if (maxPerHour > 0) {
            sentWindow.addLast(now);
        }
        return true;
    }

    private boolean breakerOpen() {
        if (breakerThreshold <= 0) {
            return false;
        }
        Deadline open = openUntil;
        if (open == null) {
            return false;
        }
        if (Instant.now().isBefore(open.at())) {
            return true;
        }
        synchronized (this) {
            if (openUntil == open) {
                openUntil = null;
                consecutiveFailures.set(0);
            }
        }
        return false;
    }

    private void attempt(Notification notification, String payload) {
        if (inFlight.incrementAndGet() > maxInFlight) {
            inFlight.decrementAndGet();
            webhookFailed.incrementAndGet();
            lastError = "webhook in-flight limit reached";
            record("webhook", "failed", 0, lastError);
            return;
        }
        try {
            int attempts = 0;
            String failure = null;
            while (attempts <= retries) {
                attempts++;
                try {
                    HttpResponse<Void> response = client.send(request(payload),
                            HttpResponse.BodyHandlers.discarding());
                    if (response.statusCode() < 400) {
                        webhookSent.incrementAndGet();
                        consecutiveFailures.set(0);
                        record("webhook", "sent", attempts, "answered " + response.statusCode());
                        audit("webhook", "sent", notification.id(), "attempts " + attempts);
                        return;
                    }
                    failure = "webhook answered " + response.statusCode();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    failure = "interrupted";
                    break;
                } catch (Exception ex) {
                    failure = ex.getClass().getSimpleName() + ": " + ex.getMessage();
                }
                if (attempts <= retries) {
                    pause(attempts);
                }
            }
            webhookFailed.incrementAndGet();
            lastError = failure == null ? "webhook delivery failed" : failure;
            record("webhook", "failed", attempts, lastError);
            audit("webhook", "failed", notification.id(), lastError);
            if (breakerThreshold > 0 && consecutiveFailures.incrementAndGet() >= breakerThreshold) {
                openUntil = new Deadline(Instant.now().plusSeconds(breakerCooldownSeconds));
                lastError = lastError + " (circuit open for " + breakerCooldownSeconds + "s)";
                EventLog.getInstance().log(LogLevel.WARN, "notify",
                        "webhook circuit opened after " + breakerThreshold + " failures");
                record("webhook", "breaker", 0, "circuit open for " + breakerCooldownSeconds + "s");
            }
        } finally {
            inFlight.decrementAndGet();
        }
    }

    private HttpRequest request(String payload) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(webhookUrl))
                .header("Content-Type", "application/json")
                .header("User-Agent", "ntd-notifier")
                .timeout(Duration.ofMillis(Math.max(100, timeoutMillis)))
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8));
        String signature = WebhookGuard.signature(payload, secret);
        if (signature != null) {
            builder.header("X-NTD-Signature", signature);
        }
        return builder.build();
    }

    private void pause(int attempt) {
        if (backoffMillis <= 0) {
            return;
        }
        long wait = backoffMillis << Math.min(6, Math.max(0, attempt - 1));
        try {
            Thread.sleep(Math.min(wait, 30_000));
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private void submit(Runnable task) {
        try {
            worker().execute(task);
        } catch (RuntimeException ex) {
            lastError = "notification worker refused a task: " + ex.getMessage();
        }
    }

    private ExecutorService worker() {
        ExecutorService current = worker;
        if (current != null) {
            return current;
        }
        synchronized (this) {
            if (worker == null) {
                ThreadFactory factory = runnable -> {
                    Thread thread = new Thread(runnable, "ntd-notify");
                    thread.setDaemon(true);
                    return thread;
                };
                worker = Executors.newFixedThreadPool(2, factory);
            }
            return worker;
        }
    }

    private Delivery record(String channel, String outcome, int attempts, String detail) {
        Delivery delivery = new Delivery(Instant.now(), channel, outcome, attempts,
                clip(detail == null ? "" : detail));
        synchronized (this) {
            if (historyMax > 0) {
                history.addLast(delivery);
                while (history.size() > historyMax) {
                    history.removeFirst();
                }
            }
        }
        return delivery;
    }

    private void audit(String channel, String outcome, String id, String detail) {
        recorder.attempt(channel, outcome, id + " " + detail);
    }

    private String channels() {
        StringBuilder out = new StringBuilder("outbox");
        if (consoleEnabled) {
            out.append("+console");
        }
        if (!webhookUrl.isEmpty()) {
            out.append("+webhook");
        }
        if (mailer != null) {
            out.append("+email");
        }
        return out.toString();
    }

    private String body(Notification notification) {
        return clip(sanitize("Network Threat Detection" + System.lineSeparator()
                + "Severity: " + notification.severity() + System.lineSeparator()
                + "Type: " + notification.attackType() + System.lineSeparator()
                + "Source: " + notification.sourceIp() + System.lineSeparator()
                + "Target: " + notification.targetIp() + System.lineSeparator()
                + "Escalation: " + notification.escalation() + System.lineSeparator()
                + "Summary: " + notification.summary() + System.lineSeparator()
                + "Alert: " + notification.id()));
    }

    private String json(Notification notification) {
        return clip("{\"id\":\"" + escape(notification.id())
                + "\",\"timestamp\":\"" + notification.timestamp()
                + "\",\"severity\":\"" + notification.severity()
                + "\",\"attackType\":\"" + escape(notification.attackType())
                + "\",\"sourceIp\":\"" + escape(notification.sourceIp())
                + "\",\"targetIp\":\"" + escape(notification.targetIp())
                + "\",\"escalation\":" + notification.escalation()
                + ",\"summary\":\"" + escape(notification.summary()) + "\"}");
    }

    private String sanitize(String value) {
        if (value == null) {
            return "";
        }
        String out = value;
        if (redact) {
            out = out.replaceAll("(?i)(password|passwd|token|secret|api[_-]?key)\\s*[=:]\\s*\\S+", "$1=***");
            out = out.replaceAll("(?i)bearer\\s+[A-Za-z0-9._-]{8,}", "bearer ***");
        }
        return out;
    }

    private String clip(String value) {
        if (maxBodyBytes <= 0 || value == null || value.length() <= maxBodyBytes) {
            return value == null ? "" : value;
        }
        return value.substring(0, Math.max(0, maxBodyBytes - 3)) + "...";
    }

    private synchronized int size() {
        return outbox.size();
    }

    private static String host(String url) {
        try {
            String value = URI.create(url).getHost();
            return value == null ? "" : value;
        } catch (RuntimeException ex) {
            return "";
        }
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

    private static Settings settings(ConfigManager config) {
        return new Settings(
                Boolean.parseBoolean(config.getString("notifications.enabled", "false")),
                severity(config.getString("notifications.minSeverity", "HIGH")),
                config.getInt("notifications.maxOutbox", 200),
                config.getString("notifications.webhook.url", ""),
                Boolean.parseBoolean(config.getString("notifications.console", "true")),
                Boolean.parseBoolean(config.getString("notifications.email.enabled", "false")),
                config.getString("notifications.email.to", ""),
                config.getInt("notifications.maxInFlight", 8),
                config.getInt("notifications.webhook.timeoutMillis", 2000),
                Boolean.parseBoolean(config.getString("notifications.allowInsecure", "false")),
                config.getInt("notifications.retries", 2),
                config.getInt("notifications.backoffMillis", 500),
                config.getInt("notifications.breakerThreshold", 5),
                config.getInt("notifications.breakerCooldownSeconds", 60),
                config.getInt("notifications.maxPerHour", 120),
                config.getInt("notifications.cooldownSeconds", 30),
                config.getInt("notifications.maxBodyBytes", 8192),
                config.getInt("notifications.historyMax", 200),
                Boolean.parseBoolean(config.getString("notifications.redact", "true")));
    }

    private static Mailer mailer(ConfigManager config) {
        if (!Boolean.parseBoolean(config.getString("notifications.email.enabled", "false"))) {
            return null;
        }
        String host = config.getString("notifications.email.host", "").trim();
        List<String> recipients = new ArrayList<>();
        for (String raw : config.getString("notifications.email.to", "").split("[,;\\s]+")) {
            if (!raw.isBlank()) {
                recipients.add(raw.trim());
            }
        }
        if (host.isEmpty() || recipients.isEmpty()) {
            EventLog.getInstance().log(LogLevel.WARN, "notify",
                    "email enabled but host or recipient is missing; the email channel stays off");
            return null;
        }
        return new SmtpMailer(host,
                config.getInt("notifications.email.port", 587),
                config.getString("notifications.email.from", "ntd@localhost"),
                recipients,
                System.getenv("NTD_SMTP_USER"),
                System.getenv("NTD_SMTP_PASSWORD"),
                Boolean.parseBoolean(config.getString("notifications.email.tls", "true")),
                config.getInt("notifications.email.timeoutMillis", 5000));
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

    private record Deadline(Instant at) {
    }
}
