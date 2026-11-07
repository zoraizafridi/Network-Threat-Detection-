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
    private int port;

    @BeforeEach
    void startServer() {
        facade = new IncidentResponseFacade(TopologyLoader.loadSample(), 42L);
        server = new WebServer(facade, 0);
        server.start(0);
        port = server.port();
        CookieManager cookies = new CookieManager();
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

    private HttpResponse<String> call(String method, String path, String json) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri(path)).timeout(Duration.ofSeconds(5));
        if ("POST".equals(method)) {
            builder.header("Content-Type", "application/json");
            builder.POST(HttpRequest.BodyPublishers.ofString(json == null ? "" : json));
        } else {
            builder.GET();
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }
}
