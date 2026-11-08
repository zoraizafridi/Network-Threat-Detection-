package pk.ooad.ntd.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.service.IncidentResponseFacade;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebServerTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private IncidentResponseFacade facade;
    private WebServer server;
    private HttpClient http;
    private CookieManager cookies;
    private int port;

    @BeforeEach
    void startServer() {
        facade = new IncidentResponseFacade(TopologyLoader.loadSample(), 42L);
        server = new WebServer(facade, 0);
        server.start(0);
        port = server.port();
        cookies = new CookieManager();
        cookies.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
        http = HttpClient.newBuilder()
                .cookieHandler(cookies)
                .connectTimeout(Duration.ofSeconds(3))
                .build();
    }

    @AfterEach
    void stopServer() {
        facade.stop();
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void requestsWithoutLoginAreRejected() throws Exception {
        assertEquals(401, call("GET", "/api/state", null).statusCode());
        assertEquals(401, call("GET", "/api/network", null).statusCode());
    }

    @Test
    void badLoginIsRejected() throws Exception {
        HttpResponse<String> response = call("POST", "/api/login",
                "{\"username\":\"admin\",\"password\":\"wrong\"}");
        assertEquals(401, response.statusCode());
    }

    @Test
    void adminLoginReturnsRole() throws Exception {
        JsonNode body = login("admin", "admin");
        assertEquals("admin", body.get("username").asText());
        assertEquals("Admin", body.get("role").asText());
    }

    @Test
    void networkReturnsSampleTopology() throws Exception {
        login("admin", "admin");
        JsonNode body = mapper.readTree(call("GET", "/api/network", null).body());
        assertEquals(18, body.get("assets").size());
        assertTrue(body.get("links").size() > 0);
        boolean found = false;
        for (JsonNode asset : body.get("assets")) {
            assertNotNull(asset.get("id"));
            assertNotNull(asset.get("name"));
            assertNotNull(asset.get("ip"));
            assertNotNull(asset.get("type"));
            assertNotNull(asset.get("criticality"));
            assertNotNull(asset.get("riskScore"));
            assertNotNull(asset.get("status"));
            if ("rt-core-1".equals(asset.get("id").asText())) {
                found = true;
            }
        }
        assertTrue(found);
        JsonNode link = body.get("links").get(0);
        assertNotNull(link.get("id"));
        assertNotNull(link.get("source"));
        assertNotNull(link.get("target"));
        assertNotNull(link.get("baseCost"));
        assertNotNull(link.get("bandwidth"));
        assertNotNull(link.get("status"));
    }

    @Test
    void attackLaunchChangesAlerts() throws Exception {
        login("admin", "admin");
        assertEquals(200, call("POST", "/api/sim/start", null).statusCode());
        JsonNode before = mapper.readTree(call("GET", "/api/alerts?limit=50", null).body());
        assertEquals(200, call("POST", "/api/attacks",
                "{\"type\":\"DOS_FLOOD\",\"src\":\"ws-ops-1\",\"dst\":\"srv-web-1\"}").statusCode());
        JsonNode after = awaitAlerts();
        assertTrue(after.size() > before.size());
    }

    @Test
    void unknownAttackTypeIsRejected() throws Exception {
        login("admin", "admin");
        HttpResponse<String> response = call("POST", "/api/attacks",
                "{\"type\":\"WORM\",\"src\":\"ws-ops-1\",\"dst\":\"srv-web-1\"}");
        assertEquals(400, response.statusCode());
    }

    @Test
    void viewerCannotLaunchAttack() throws Exception {
        JsonNode body = login("viewer", "viewer");
        assertEquals("Viewer", body.get("role").asText());
        HttpResponse<String> response = call("POST", "/api/attacks",
                "{\"type\":\"DOS_FLOOD\",\"src\":\"ws-ops-1\",\"dst\":\"srv-web-1\"}");
        assertEquals(403, response.statusCode());
    }

    @Test
    void responseRunReturnsBackbone() throws Exception {
        login("admin", "admin");
        JsonNode body = mapper.readTree(call("POST", "/api/response/run", null).body());
        assertTrue(body.get("backbone").get("links").isArray());
        assertFalse(body.get("backbone").get("totalWeight").isNull());
        assertTrue(body.get("backbone").has("connected"));
        assertTrue(body.get("backbone").get("unreachable").isArray());
        assertTrue(body.get("assignment").get("teams").isArray());
        assertTrue(body.get("assignment").has("stateCount"));
    }

    @Test
    void streamDeliversAlertAfterAttack() throws Exception {
        login("admin", "admin");
        HttpRequest request = HttpRequest.newBuilder(uri("/api/stream"))
                .timeout(Duration.ofSeconds(8))
                .header("Accept", "text/event-stream")
                .GET()
                .build();
        HttpResponse<java.io.InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        assertEquals(200, response.statusCode());
        ExecutorService reader = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "ntd-sse-test");
            thread.setDaemon(true);
            return thread;
        });
        Future<String> alertEvent = reader.submit(() -> {
            try (BufferedReader lines = new BufferedReader(
                    new InputStreamReader(response.body(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = lines.readLine()) != null) {
                    if (line.startsWith("event:") && line.contains("alert")) {
                        return line;
                    }
                }
            }
            return null;
        });
        try {
            assertEquals(200, call("POST", "/api/sim/start", null).statusCode());
            assertEquals(200, call("POST", "/api/attacks",
                    "{\"type\":\"DOS_FLOOD\",\"src\":\"ws-ops-1\",\"dst\":\"srv-web-1\"}").statusCode());
            assertNotNull(alertEvent.get(5, TimeUnit.SECONDS));
        } finally {
            reader.shutdownNow();
            response.body().close();
        }
    }

    private JsonNode login(String username, String password) throws Exception {
        HttpResponse<String> response = call("POST", "/api/login",
                "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}");
        assertEquals(200, response.statusCode(), response.body());
        return mapper.readTree(response.body());
    }

    private JsonNode awaitAlerts() throws Exception {
        java.util.concurrent.CompletableFuture<JsonNode> done = new java.util.concurrent.CompletableFuture<>();
        java.util.concurrent.ScheduledExecutorService scheduler = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "ntd-alert-poll");
            thread.setDaemon(true);
            return thread;
        });
        Runnable poll = new Runnable() {
            private int tries;

            @Override
            public void run() {
                try {
                    JsonNode body = mapper.readTree(call("GET", "/api/alerts?limit=50", null).body());
                    if ((body.isArray() && body.size() > 0) || ++tries > 40) {
                        done.complete(body);
                    } else {
                        scheduler.schedule(this, 25, TimeUnit.MILLISECONDS);
                    }
                } catch (Exception ex) {
                    done.completeExceptionally(ex);
                }
            }
        };
        scheduler.execute(poll);
        try {
            return done.get(5, TimeUnit.SECONDS);
        } finally {
            scheduler.shutdownNow();
        }
    }

    @Test
    void securityHeadersAndCookieFlagsArePresent() throws Exception {
        HttpResponse<String> response = call("GET", "/api/state", null);
        assertTrue(response.headers().firstValue("X-Frame-Options").isPresent());
        assertEquals("DENY", response.headers().firstValue("X-Frame-Options").get());
        assertEquals("nosniff", response.headers().firstValue("X-Content-Type-Options").get());
        assertTrue(response.headers().firstValue("Content-Security-Policy").isPresent());
        String csp = response.headers().firstValue("Content-Security-Policy").get();
        assertTrue(csp.contains("object-src 'none'"), csp);
        assertTrue(csp.contains("frame-ancestors 'none'"), csp);
        assertTrue(csp.contains("base-uri 'self'"), csp);
        assertTrue(response.headers().firstValue("Referrer-Policy").isPresent());
    }

    @Test
    void crossOriginPostIsRejected() throws Exception {
        login("admin", "admin");
        HttpRequest request = HttpRequest.newBuilder(uri("/api/sim/start"))
                .header("Content-Type", "application/json")
                .header("X-CSRF-Token", csrf())
                .header("Origin", "https://evil.example")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, response.statusCode());
    }

    @Test
    void attackWithSameSourceAndTargetIsRejected() throws Exception {
        login("admin", "admin");
        String json = "{\"type\":\"PORT_SCAN\",\"src\":\"srv-web-1\",\"dst\":\"srv-web-1\"}";
        HttpResponse<String> response = call("POST", "/api/attacks", json);
        assertEquals(400, response.statusCode());
    }

    @Test
    void unknownApiPathReturns404() throws Exception {
        assertEquals(404, call("GET", "/api/does-not-exist", null).statusCode());
        login("admin", "admin");
        assertEquals(404, call("GET", "/api/nope", null).statusCode());
    }

    @Test
    void postWithoutCsrfHeaderIsRejected() throws Exception {
        login("admin", "admin");
        HttpRequest request = HttpRequest.newBuilder(uri("/api/sim/start"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        assertEquals(403, http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
    }

    @Test
    void csrfCookieCarriesStrictSameSiteAndMaxAge() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(uri("/api/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"username\":\"admin\",\"password\":\"admin\"}"))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        String setCookie = response.headers().allValues("Set-Cookie").stream()
                .filter(value -> value.startsWith("csrf="))
                .findFirst()
                .orElse("");
        assertTrue(setCookie.startsWith("csrf="), setCookie);
        assertTrue(setCookie.contains("Path=/"), setCookie);
        assertTrue(setCookie.contains("Max-Age="), setCookie);
        assertTrue(setCookie.contains("SameSite=Strict"), setCookie);
    }

    @Test
    void nonJsonContentTypeIsRejected() throws Exception {
        login("admin", "admin");
        HttpRequest request = HttpRequest.newBuilder(uri("/api/attacks"))
                .header("Content-Type", "text/plain")
                .header("X-CSRF-Token", csrf())
                .POST(HttpRequest.BodyPublishers.ofString("{\"type\":\"DOS_FLOOD\"}"))
                .build();
        assertEquals(415, http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
    }

    @Test
    void repeatedLoginFailuresAreThrottled() throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            assertEquals(401, call("POST", "/api/login",
                    "{\"username\":\"admin\",\"password\":\"wrong\"}").statusCode());
        }
        HttpResponse<String> blocked = call("POST", "/api/login",
                "{\"username\":\"admin\",\"password\":\"admin\"}");
        assertEquals(429, blocked.statusCode());
        assertTrue(blocked.headers().firstValue("Retry-After").isPresent());
    }

    @Test
    void injectedAttackAlertsAreFlaggedAsSimulated() throws Exception {
        login("admin", "admin");
        assertEquals(200, call("POST", "/api/sim/start", null).statusCode());
        assertEquals(200, call("POST", "/api/attacks",
                "{\"type\":\"DOS_FLOOD\",\"src\":\"ws-ops-1\",\"dst\":\"srv-web-1\"}").statusCode());
        JsonNode alert = awaitAlert("DOS_FLOOD");
        assertNotNull(alert, "expected a DOS_FLOOD alert");
        assertTrue(alert.get("simulated").asBoolean(), "injected alerts must be marked simulated");
        assertFalse(alert.get("detectorName").asText().isBlank());
    }

    @Test
    void streamSendsHelloEventOnSubscribe() throws Exception {
        login("admin", "admin");
        HttpRequest request = HttpRequest.newBuilder(uri("/api/stream"))
                .timeout(Duration.ofSeconds(8))
                .header("Accept", "text/event-stream")
                .GET()
                .build();
        HttpResponse<java.io.InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        assertEquals(200, response.statusCode());
        try (BufferedReader lines = new BufferedReader(
                new InputStreamReader(response.body(), StandardCharsets.UTF_8))) {
            String event = null;
            String line;
            while ((line = lines.readLine()) != null) {
                if (line.startsWith("event:")) {
                    event = line;
                    break;
                }
            }
            assertNotNull(event, "stream must greet the client");
            assertTrue(event.contains("hello"), event);
        } finally {
            response.body().close();
        }
    }

    @Test
    void configEndpointIsAdminOnly() throws Exception {
        login("viewer", "viewer");
        assertEquals(403, call("GET", "/api/config", null).statusCode());
        JsonNode body = login("admin", "admin");
        assertEquals("Admin", body.get("role").asText());
        HttpResponse<String> response = call("GET", "/api/config", null);
        assertEquals(200, response.statusCode());
        JsonNode config = mapper.readTree(response.body());
        assertTrue(config.get("thresholds").has("risk.compromiseThreshold"));
        assertTrue(config.get("session").get("csrfEnabled").asBoolean());
        assertEquals(3, config.get("accounts").size());
    }

    @Test
    void negativeAlertLimitIsRejected() throws Exception {
        login("admin", "admin");
        assertEquals(400, call("GET", "/api/alerts?limit=-1", null).statusCode());
    }

    @Test
    void flowsAreRecordedWhileTheSimulatorRuns() throws Exception {
        login("admin", "admin");
        assertEquals(200, call("POST", "/api/sim/start", null).statusCode());
        // The simulator only emits background traffic in auto mode.
        assertEquals(200, call("POST", "/api/sim/auto", "{\"on\":true}").statusCode());
        JsonNode rows = awaitFlows();
        assertTrue(rows.size() > 0, "the flow table must fill while the simulator runs");
        JsonNode flow = rows.get(0);
        assertNotNull(flow.get("id"));
        assertNotNull(flow.get("srcIp"));
        assertNotNull(flow.get("dstIp"));
        assertTrue(flow.get("srcPort").asInt() > 0);
        assertTrue(flow.get("dstPort").asInt() > 0);
        assertTrue(flow.get("bytesOut").asLong() > 0);
        assertTrue(flow.get("packets").asLong() > 0);
        assertFalse(flow.get("startTime").asText().isBlank());
        assertFalse(flow.get("label").asText().isBlank());
    }

    @Test
    void flowFiltersAreValidated() throws Exception {
        login("admin", "admin");
        assertEquals(400, call("GET", "/api/flows?port=abc", null).statusCode());
        assertEquals(400, call("GET", "/api/flows?port=70000", null).statusCode());
        assertEquals(400, call("GET", "/api/flows?limit=-1", null).statusCode());
        assertEquals(400, call("GET", "/api/flows?from=not-a-time", null).statusCode());
        assertEquals(200, call("GET", "/api/flows?limit=5", null).statusCode());
        assertEquals(200, call("GET", "/api/flows?src=10.0.0.5&dst=10.0.0.9&port=80", null).statusCode());
    }

    @Test
    void viewerMayReadFlows() throws Exception {
        login("viewer", "viewer");
        assertEquals(200, call("GET", "/api/flows", null).statusCode());
    }

    private JsonNode awaitFlows() throws Exception {
        long deadline = System.currentTimeMillis() + 5000;
        JsonNode body = mapper.createArrayNode();
        while (System.currentTimeMillis() < deadline) {
            body = mapper.readTree(call("GET", "/api/flows?limit=20", null).body());
            if (body.isArray() && body.size() > 0) {
                return body;
            }
            Thread.sleep(25);
        }
        return body;
    }

    private JsonNode awaitAlert(String attackType) throws Exception {
        long deadline = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < deadline) {
            JsonNode body = mapper.readTree(call("GET", "/api/alerts?limit=50", null).body());
            if (body.isArray()) {
                for (JsonNode alert : body) {
                    if (attackType.equals(alert.path("attackType").asText())) {
                        return alert;
                    }
                }
            }
            Thread.sleep(25);
        }
        return null;
    }

    private HttpResponse<String> call(String method, String path, String json) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri(path)).timeout(Duration.ofSeconds(5));
        if ("POST".equals(method)) {
            builder.header("Content-Type", "application/json");
            String token = csrf();
            if (token != null) {
                builder.header("X-CSRF-Token", token);
            }
            builder.POST(HttpRequest.BodyPublishers.ofString(json == null ? "" : json));
        } else {
            builder.GET();
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String csrf() {
        return cookies.getCookieStore().getCookies().stream()
                .filter(cookie -> "csrf".equals(cookie.getName()))
                .map(java.net.HttpCookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }
}
