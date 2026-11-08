package pk.ooad.ntd.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.service.IncidentResponseFacade;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OperationsApiTest {

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
    @DisplayName("The ML status is readable and says disabled rather than pretending")
    void mlStatusWhenOff() throws Exception {
        login("admin", "admin");
        HttpResponse<String> response = call("GET", "/api/ml/status", null);
        assertEquals(200, response.statusCode());
        JsonNode body = mapper.readTree(response.body());
        assertFalse(body.get("enabled").asBoolean());
        assertEquals("disabled", body.get("modelState").asText());
        assertEquals(0, body.get("samples").asInt());
        assertEquals(0, body.get("clusters").asInt());
        assertEquals(0.9, body.get("threshold").asDouble(), 1e-9);
    }

    @Test
    @DisplayName("The correlation status is readable and reports its rule")
    void correlationStatusWhenOff() throws Exception {
        login("admin", "admin");
        HttpResponse<String> response = call("GET", "/api/correlation/status", null);
        assertEquals(200, response.statusCode());
        JsonNode body = mapper.readTree(response.body());
        assertFalse(body.get("enabled").asBoolean());
        assertEquals(2, body.get("minSignals").asInt());
        assertEquals(600, body.get("windowSeconds").asInt());
        assertEquals(0, body.get("signals").asInt());
    }

    @Test
    @DisplayName("Notifications answer with an empty bounded outbox")
    void notificationsWhenOff() throws Exception {
        login("admin", "admin");
        HttpResponse<String> response = call("GET", "/api/notifications", null);
        assertEquals(200, response.statusCode());
        JsonNode body = mapper.readTree(response.body());
        assertFalse(body.get("enabled").asBoolean());
        assertEquals("HIGH", body.get("minimumSeverity").asText());
        assertTrue(body.get("notifications").isArray());
        assertEquals(0, body.get("notifications").size());
    }

    @Test
    @DisplayName("Containment reads back off, refuses an order with 409, and 404s a release")
    void containmentWhenOff() throws Exception {
        login("admin", "admin");
        JsonNode body = mapper.readTree(call("GET", "/api/containment", null).body());
        assertFalse(body.get("enabled").asBoolean());
        assertFalse(body.get("auto").asBoolean());
        assertFalse(body.get("enforce").asBoolean());
        assertTrue(body.get("blocked").isArray());
        assertEquals(0, body.get("blocked").size());

        HttpResponse<String> blocked = call("POST", "/api/containment",
                "{\"ip\":\"10.0.0.5\",\"minutes\":10,\"reason\":\"test\"}");
        assertEquals(409, blocked.statusCode());
        assertTrue(blocked.body().contains("disabled"));

        assertEquals(404, call("POST", "/api/containment/release", "{\"ip\":\"10.0.0.5\"}").statusCode());
    }

    @Test
    @DisplayName("Compliance is Admin only and reports the real disabled state")
    void complianceIsAdminOnly() throws Exception {
        login("viewer", "viewer");
        assertEquals(403, call("GET", "/api/compliance/summary", null).statusCode());

        login("admin", "admin");
        HttpResponse<String> response = call("GET", "/api/compliance/summary", null);
        assertEquals(200, response.statusCode());
        JsonNode body = mapper.readTree(response.body());
        assertFalse(body.get("storeEnabled").asBoolean());
        assertFalse(body.get("forensicsEnabled").asBoolean());
        assertFalse(body.get("notificationsEnabled").asBoolean());
        assertFalse(body.get("containmentEnabled").asBoolean());
        assertEquals(1_440, body.get("retentionMinutes").asInt());
        assertTrue(body.get("auditCapacity").asInt() >= 1);
        assertNotNull(body.get("retentionCutoff"));
    }

    @Test
    @DisplayName("Evidence export is Admin only and 409s while forensics is off")
    void evidenceExportIsAdminOnlyAndGated() throws Exception {
        login("viewer", "viewer");
        assertEquals(403, call("POST", "/api/forensics/export", "").statusCode());

        login("admin", "admin");
        assertEquals(409, call("POST", "/api/forensics/export", "").statusCode());
    }

    @Test
    @DisplayName("Stored flow history answers 503 while the durable store is off")
    void flowHistoryReportsStoreOff() throws Exception {
        login("admin", "admin");
        assertEquals(503, call("GET", "/api/flows/history", null).statusCode());
        assertEquals(200, call("GET", "/api/flows", null).statusCode());
    }

    @Test
    @DisplayName("The audit trail is Admin only and holds the login that opened the session")
    void auditTrailIsAdminOnly() throws Exception {
        login("viewer", "viewer");
        assertEquals(403, call("GET", "/api/audit", null).statusCode());

        login("admin", "admin");
        HttpResponse<String> response = call("GET", "/api/audit", null);
        assertEquals(200, response.statusCode());
        JsonNode body = mapper.readTree(response.body());
        assertTrue(body.get("entries").isArray());
        assertTrue(body.get("entries").size() >= 1);
        boolean adminLoginRecorded = false;
        boolean viewerLoginRecorded = false;
        for (JsonNode entry : body.get("entries")) {
            if ("auth.login".equals(entry.get("action").asText())) {
                assertEquals("ALLOWED", entry.get("outcome").asText());
                if ("admin".equals(entry.get("actor").asText())) {
                    adminLoginRecorded = true;
                }
                if ("viewer".equals(entry.get("actor").asText())) {
                    viewerLoginRecorded = true;
                }
            }
        }
        assertTrue(adminLoginRecorded, "the successful admin login must be in the trail");
        assertTrue(viewerLoginRecorded, "the earlier viewer login is in the trail too");
        assertTrue(body.get("capacity").asInt() >= 1);
    }

    @Test
    @DisplayName("A viewer may read operations status but not order containment")
    void viewerCanReadButNotContain() throws Exception {
        login("viewer", "viewer");
        assertEquals(200, call("GET", "/api/ml/status", null).statusCode());
        assertEquals(200, call("GET", "/api/containment", null).statusCode());
        assertEquals(403, call("POST", "/api/containment", "{\"ip\":\"10.0.0.5\"}").statusCode());
        assertEquals(403, call("POST", "/api/containment/release", "{\"ip\":\"10.0.0.5\"}").statusCode());
    }

    private JsonNode login(String username, String password) throws Exception {
        HttpResponse<String> response = call("POST", "/api/login",
                "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}");
        assertEquals(200, response.statusCode(), "login for " + username);
        return mapper.readTree(response.body());
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
