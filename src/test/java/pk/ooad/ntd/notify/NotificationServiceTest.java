package pk.ooad.ntd.notify;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Severity;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NotificationServiceTest {

    private final Instant base = Instant.parse("2026-11-08T05:00:00Z");
    private final AlertFactory factory = new AlertFactory();

    private Alert alert(Severity severity, String source, Instant at) {
        return factory.create(severity, AttackType.BRUTE_FORCE, source, "10.0.0.9",
                "RateThresholdDetector", "failed logins", at);
    }

    @Test
    @DisplayName("A disabled service records nothing")
    void disabledServiceRecordsNothing() {
        NotificationService service = new NotificationService(false, Severity.LOW, 10, "", 4, 500);
        service.onAlert(alert(Severity.CRITICAL, "10.0.0.5", base));
        assertFalse(service.status().enabled());
        assertTrue(service.recent(10).isEmpty());
        assertEquals(0, service.status().recorded());
    }

    @Test
    @DisplayName("The severity floor decides what is delivered")
    void severityFloorFilters() {
        NotificationService service = new NotificationService(true, Severity.HIGH, 10, "", 4, 500);
        service.onAlert(alert(Severity.LOW, "10.0.0.5", base));
        assertTrue(service.recent(10).isEmpty());

        service.onAlert(alert(Severity.HIGH, "10.0.0.6", base.plusSeconds(1)));
        service.onAlert(alert(Severity.CRITICAL, "10.0.0.7", base.plusSeconds(2)));
        assertEquals(2, service.status().recorded());
        List<NotificationService.Notification> rows = service.recent(10);
        assertEquals(2, rows.size());
        assertEquals("10.0.0.7", rows.get(0).sourceIp(), "newest first");
        assertEquals("HIGH", service.status().minimumSeverity());
        assertEquals("outbox", rows.get(0).channel());
        assertTrue(rows.get(0).summary().startsWith("RateThresholdDetector: "));
    }

    @Test
    @DisplayName("The outbox is bounded and the eviction is counted")
    void outboxIsBounded() {
        NotificationService service = new NotificationService(true, Severity.LOW, 2, "", 4, 500);
        service.onAlert(alert(Severity.HIGH, "10.0.0.1", base));
        service.onAlert(alert(Severity.HIGH, "10.0.0.2", base.plusSeconds(1)));
        service.onAlert(alert(Severity.HIGH, "10.0.0.3", base.plusSeconds(2)));

        NotificationService.Status status = service.status();
        assertEquals(2, status.outboxSize());
        assertEquals(1, status.dropped());
        assertEquals(3, status.recorded());
        assertEquals(2, service.recent(10).size());
        assertEquals("10.0.0.3", service.recent(10).get(0).sourceIp());

        service.reset();
        assertEquals(0, service.status().outboxSize());
        assertEquals(0, service.status().recorded());
        assertTrue(service.recent(10).isEmpty());
    }

    @Test
    @DisplayName("The webhook receives one JSON body per delivered alert")
    void webhookReceivesJson() throws Exception {
        AtomicInteger posts = new AtomicInteger();
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> contentType = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/hook", exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            posts.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/hook";
            NotificationService service = new NotificationService(true, Severity.HIGH, 10, url, 4, 2_000);
            assertTrue(service.status().webhookConfigured());

            Alert alert = alert(Severity.CRITICAL, "10.0.0.9", base);
            service.onAlert(alert);

            long deadline = System.currentTimeMillis() + 5_000;
            while (service.status().webhookSent() == 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
            assertEquals(1, service.status().webhookSent());
            assertEquals(0, service.status().webhookFailed());
            assertEquals(1, posts.get());
            assertTrue(contentType.get().startsWith("application/json"));
            assertTrue(body.get().contains("\"id\":\"" + alert.getId() + "\""));
            assertTrue(body.get().contains("\"severity\":\"CRITICAL\""));
            assertTrue(body.get().contains("\"sourceIp\":\"10.0.0.9\""));
            assertTrue(service.recent(5).get(0).channel().contains("webhook"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("An unreachable webhook is reported rather than thrown")
    void failingWebhookIsCounted() throws Exception {
        NotificationService service = new NotificationService(true, Severity.LOW, 10,
                "http://127.0.0.1:1/hook", 2, 300);
        service.onAlert(alert(Severity.HIGH, "10.0.0.5", base));
        long deadline = System.currentTimeMillis() + 5_000;
        while (service.status().webhookFailed() == 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        assertEquals(1, service.status().webhookFailed());
        assertFalse(service.status().lastError().isEmpty());
        assertEquals(1, service.recent(5).size(), "the row is kept even when delivery fails");
    }

    @Test
    @DisplayName("A malformed webhook URL does not escape onAlert")
    void malformedWebhookIsContained() {
        NotificationService service = new NotificationService(true, Severity.LOW, 10, "not a url", 2, 300);
        service.onAlert(alert(Severity.HIGH, "10.0.0.5", base));
        assertEquals(1, service.status().recorded());
        assertEquals(1, service.status().webhookFailed());
        assertFalse(service.status().lastError().isEmpty());
    }

    @Test
    @DisplayName("A null minimum severity falls back to HIGH")
    void severityFallback() {
        NotificationService service = new NotificationService(true, null, 10, "", 4, 500);
        assertEquals("HIGH", service.status().minimumSeverity());
        service.onAlert(alert(Severity.CRITICAL, "10.0.0.5", base));
        assertEquals(1, service.status().recorded());
    }
}
