package pk.ooad.ntd.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HandlerType;
import pk.ooad.ntd.domain.Admin;
import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.MitigationTask;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.ResponsePlan;
import pk.ooad.ntd.domain.SecurityAnalyst;
import pk.ooad.ntd.domain.User;
import pk.ooad.ntd.domain.Viewer;
import pk.ooad.ntd.service.Incident;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.util.ConfigManager;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

public class ApiRoutes {
    private static final Set<String> API_PATHS = Set.of(
            "/api/login", "/api/logout", "/api/state", "/api/network",
            "/api/sim/start", "/api/sim/stop", "/api/sim/reset", "/api/sim/auto",
            "/api/attacks", "/api/alerts", "/api/incidents", "/api/response/run",
            "/api/report", "/api/config", "/api/stream");
    private static final String CSRF_COOKIE = "csrf";
    private static final String CSRF_HEADER = "X-CSRF-Token";
    private static final String JSON_TYPE = "application/json";

    private final IncidentResponseFacade facade;
    private final StreamBroadcaster broadcaster;
    private final ReentrantLock lock;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ConfigManager config = ConfigManager.getInstance();
    private final LoginThrottle loginThrottle = new LoginThrottle();
    private final SecureRandom random = new SecureRandom();
    private final int alertBuffer;
    private final boolean csrfEnabled;
    private final int sessionMaxAgeSeconds;
    private final boolean secureCookie;

    public ApiRoutes(IncidentResponseFacade facade, StreamBroadcaster broadcaster, ReentrantLock lock) {
        this.facade = facade;
        this.broadcaster = broadcaster;
        this.lock = lock;
        this.alertBuffer = Math.max(1, config.getInt("alerts.buffer.max", 500));
        this.csrfEnabled = Boolean.parseBoolean(config.getString("auth.csrf.enabled", "true"));
        this.sessionMaxAgeSeconds = Math.max(60, config.getInt("auth.session.timeoutSeconds", 28800));
        this.secureCookie = Boolean.parseBoolean(config.getString("auth.session.secureCookie", "false"));
        broadcaster.setEncoders(this::alertJson, this::networkJson, this::stateJson, this::incidentsJson);
    }

    public void register(Javalin app) {
        app.before(ctx -> {
            if (!ctx.path().startsWith("/api")) {
                return;
            }
            if (!API_PATHS.contains(ctx.path())) {
                ctx.status(404).result("");
                ctx.skipRemainingHandlers();
                return;
            }
            if ("/api/login".equals(ctx.path()) && ctx.method() == HandlerType.POST) {
                return;
            }
            if (ctx.sessionAttribute("username") == null) {
                ctx.status(401).result("");
                ctx.skipRemainingHandlers();
                return;
            }
            if (csrfEnabled && requiresCsrfToken(ctx)) {
                enforceCsrf(ctx);
            }
        });

        app.post("/api/login", this::login);
        app.post("/api/logout", this::logout);
        app.get("/api/state", this::state);
        app.get("/api/network", this::network);
        app.get("/api/config", this::configuration);
        app.post("/api/sim/start", ctx -> simControl(ctx, () -> facade.start(), false));
        app.post("/api/sim/stop", ctx -> simControl(ctx, () -> facade.stop(), false));
        app.post("/api/sim/reset", ctx -> simControl(ctx, () -> facade.reset(), true));
        app.post("/api/sim/auto", this::auto);
        app.post("/api/attacks", this::attack);
        app.get("/api/alerts", this::alerts);
        app.get("/api/incidents", this::incidents);
        app.post("/api/response/run", this::response);
        app.get("/api/report", this::report);
        app.sse("/api/stream", client -> {
            client.keepAlive();
            broadcaster.addClient(client);
            client.onClose(() -> broadcaster.removeClient(client));
        });
    }

    private void login(Context ctx) {
        if (rejectsContentType(ctx)) {
            return;
        }
        JsonNode body = readJson(ctx);
        if (body == null) {
            ctx.status(400);
            return;
        }
        String username = text(body, "username");
        String password = text(body, "password");
        String throttleKey = username + "|" + ctx.ip();
        if (!loginThrottle.allowed(throttleKey)) {
            ctx.header("Retry-After", String.valueOf(loginThrottle.retryAfterSeconds(throttleKey)));
            ctx.status(429).result("");
            return;
        }
        User user;
        lock.lock();
        try {
            user = facade.login(username, password);
        } catch (IllegalArgumentException ex) {
            loginThrottle.recordFailure(throttleKey);
            ctx.status(401).result("");
            return;
        } finally {
            lock.unlock();
        }
        loginThrottle.clear(throttleKey);
        String role = roleName(user);
        ctx.sessionAttribute("username", user.getUsername());
        ctx.sessionAttribute("role", role);
        ctx.sessionAttribute("canLaunchAttack", user.canLaunchAttack());
        ctx.sessionAttribute("canRunPlanner", user.canRunPlanner());
        setCsrfCookie(ctx);
        ctx.json(Map.of("username", user.getUsername(), "role", role));
    }

    private void logout(Context ctx) {
        if (ctx.req().getSession(false) != null) {
            ctx.req().getSession(false).invalidate();
        }
        ctx.status(200).result("");
    }

    private void state(Context ctx) {
        if (csrfEnabled && ctx.cookie(CSRF_COOKIE) == null) {
            setCsrfCookie(ctx);
        }
        ctx.json(buildState(ctx.sessionAttribute("username"), ctx.sessionAttribute("role")));
    }

    private void network(Context ctx) {
        ctx.json(networkBody());
    }

    private void auto(Context ctx) {
        if (!canControlSim(ctx)) {
            ctx.status(403).result("");
            return;
        }
        if (rejectsContentType(ctx)) {
            return;
        }
        JsonNode body = readJson(ctx);
        if (body == null || !body.has("on") || !body.get("on").isBoolean()) {
            ctx.status(400);
            return;
        }
        boolean on = body.get("on").booleanValue();
        lock.lock();
        try {
            facade.setAutoMode(on);
        } finally {
            lock.unlock();
        }
        broadcaster.broadcastState();
        broadcaster.broadcastIncidents();
        ctx.status(200).result("");
    }

    private void attack(Context ctx) {
        if (!Boolean.TRUE.equals(ctx.sessionAttribute("canLaunchAttack"))) {
            ctx.status(403).result("");
            return;
        }
        if (rejectsContentType(ctx)) {
            return;
        }
        JsonNode body = readJson(ctx);
        if (body == null) {
            ctx.status(400);
            return;
        }
        AttackType type;
        try {
            type = AttackType.valueOf(text(body, "type"));
        } catch (IllegalArgumentException ex) {
            ctx.status(400);
            return;
        }
        String srcId = text(body, "src");
        String dstId = text(body, "dst");
        lock.lock();
        try {
            Network network = facade.getNetwork();
            NetworkAsset src = network.getAsset(srcId);
            NetworkAsset dst = network.getAsset(dstId);
            if (src == null || dst == null || srcId.equals(dstId) || src.getIp().equals(dst.getIp())) {
                ctx.status(400);
                return;
            }
            facade.launchAttack(type, src.getIp(), dst.getIp());
        } finally {
            lock.unlock();
        }
        ctx.status(200).result("");
    }

    private void alerts(Context ctx) {
        String raw = ctx.queryParam("limit");
        int limit = alertBuffer;
        if (raw != null) {
            try {
                limit = Integer.parseInt(raw);
            } catch (NumberFormatException ex) {
                ctx.status(400);
                return;
            }
        }
        if (limit < 0) {
            ctx.status(400);
            return;
        }
        if (limit > alertBuffer) {
            limit = alertBuffer;
        }
        List<Dtos.AlertDto> alerts = new ArrayList<>();
        for (Alert alert : broadcaster.getRecentAlerts(limit)) {
            alerts.add(alertDto(alert));
        }
        ctx.json(alerts);
    }

    private void incidents(Context ctx) {
        List<Dtos.IncidentDto> rows = new ArrayList<>();
        lock.lock();
        try {
            for (Incident incident : facade.getIncidents()) {
                rows.add(incidentDto(incident));
            }
        } finally {
            lock.unlock();
        }
        ctx.json(rows);
    }

    private void response(Context ctx) {
        if (!Boolean.TRUE.equals(ctx.sessionAttribute("canRunPlanner"))) {
            ctx.status(403).result("");
            return;
        }
        if (rejectsContentType(ctx)) {
            return;
        }
        Set<String> excludedHosts = new LinkedHashSet<>();
        Map<String, Integer> capacities = new LinkedHashMap<>();
        String raw = ctx.body();
        if (raw != null && !raw.isBlank()) {
            JsonNode node;
            try {
                node = mapper.readTree(raw);
            } catch (JsonProcessingException ex) {
                ctx.status(400).result("");
                return;
            }
            lock.lock();
            try {
                Network network = facade.getNetwork();
                JsonNode excludedNode = node.get("excludedHostIds");
                if (excludedNode != null && excludedNode.isArray()) {
                    for (JsonNode idNode : excludedNode) {
                        if (!idNode.isTextual() || network.getAsset(idNode.asText()) == null) {
                            ctx.status(400).result("");
                            return;
                        }
                        excludedHosts.add(idNode.asText());
                    }
                }
                JsonNode capacityNode = node.get("teamCapacities");
                if (capacityNode != null && capacityNode.isArray()) {
                    for (JsonNode row : capacityNode) {
                        String name = row.path("name").asText("");
                        int capacity = row.path("capacity").asInt(-1);
                        boolean known = false;
                        for (AnalystTeam team : facade.listTeams()) {
                            if (team.getName().equals(name)) {
                                known = true;
                            }
                        }
                        if (!known || capacity < 1) {
                            ctx.status(400).result("");
                            return;
                        }
                        capacities.put(name, capacity);
                    }
                }
            } finally {
                lock.unlock();
            }
        }
        ResponsePlan plan;
        lock.lock();
        try {
            plan = excludedHosts.isEmpty() && capacities.isEmpty()
                    ? facade.runResponse()
                    : facade.runResponse(excludedHosts, capacities);
        } finally {
            lock.unlock();
        }
        List<String> links = new ArrayList<>();
        List<Map<String, Object>> linkEnds = new ArrayList<>();
        for (Link link : plan.getBackbone().getChosenLinks()) {
            links.add(link.getId());
            Map<String, Object> end = new LinkedHashMap<>();
            end.put("id", link.getId());
            end.put("sourceId", link.getSource().getId());
            end.put("sourceName", link.getSource().getName());
            end.put("targetId", link.getTarget().getId());
            end.put("targetName", link.getTarget().getName());
            linkEnds.add(end);
        }
        List<String> unreachable = new ArrayList<>();
        for (NetworkAsset asset : plan.getBackbone().getUnreachable()) {
            unreachable.add(asset.getId());
        }
        Map<String, Object> backbone = new LinkedHashMap<>();
        backbone.put("links", links);
        backbone.put("totalWeight", plan.getBackbone().getTotalWeight());
        backbone.put("connected", plan.getBackbone().isConnected());
        backbone.put("unreachable", unreachable);
        backbone.put("linkEnds", linkEnds);

        List<Map<String, Object>> teams = new ArrayList<>();
        for (Map.Entry<pk.ooad.ntd.domain.AnalystTeam, List<MitigationTask>> entry
                : plan.getAssignment().getAssignments().entrySet()) {
            List<String> tasks = new ArrayList<>();
            List<Map<String, Object>> taskDetails = new ArrayList<>();
            for (MitigationTask task : entry.getValue()) {
                tasks.add(task.getId());
                Map<String, Object> detail = new LinkedHashMap<>();
                detail.put("id", task.getId());
                detail.put("hostId", task.getTarget().getId());
                detail.put("hostName", task.getTarget().getName());
                detail.put("value", task.getValue());
                detail.put("cost", task.getCost());
                taskDetails.add(detail);
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("team", entry.getKey().getName());
            row.put("tasks", tasks);
            row.put("taskDetails", taskDetails);
            teams.add(row);
        }
        List<String> excluded = new ArrayList<>();
        for (MitigationTask task : plan.getAssignment().getExcluded()) {
            excluded.add(task.getId());
        }
        Map<String, Object> assignment = new LinkedHashMap<>();
        assignment.put("teams", teams);
        assignment.put("totalValue", plan.getAssignment().getTotalValue());
        assignment.put("excluded", excluded);
        assignment.put("stateCount", plan.getAssignment().getStateCount());
        assignment.put("excludedHosts", new ArrayList<>(excludedHosts));
        List<Map<String, Object>> teamMeta = new ArrayList<>();
        for (AnalystTeam team : facade.listTeams()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", team.getName());
            row.put("capacity", capacities.getOrDefault(team.getName(), team.getCapacity()));
            teamMeta.add(row);
        }
        assignment.put("teamsMeta", teamMeta);
        ctx.json(new Dtos.PlanDto(backbone, assignment));
    }

    private void report(Context ctx) {
        String text;
        lock.lock();
        try {
            text = facade.generateReport();
        } finally {
            lock.unlock();
        }
        ctx.json(Map.of("text", text));
    }

    private void simControl(Context ctx, Runnable action, boolean reset) {
        if (!canControlSim(ctx)) {
            ctx.status(403).result("");
            return;
        }
        lock.lock();
        try {
            action.run();
        } finally {
            lock.unlock();
        }
        if (reset) {
            broadcaster.clearRecentAlerts();
            broadcaster.requestNetwork();
        }
        broadcaster.broadcastState();
        broadcaster.broadcastIncidents();
        ctx.status(200).result("");
    }

    private boolean canControlSim(Context ctx) {
        return Boolean.TRUE.equals(ctx.sessionAttribute("canLaunchAttack"))
                || Boolean.TRUE.equals(ctx.sessionAttribute("canRunPlanner"));
    }

    private Map<String, Object> networkBody() {
        List<Dtos.AssetDto> assets = new ArrayList<>();
        List<Dtos.LinkDto> links = new ArrayList<>();
        lock.lock();
        try {
            Network network = facade.getNetwork();
            for (NetworkAsset asset : network.getAssets()) {
                assets.add(new Dtos.AssetDto(
                        asset.getId(),
                        asset.getName(),
                        asset.getIp(),
                        asset.getType().name(),
                        asset.getCriticality(),
                        asset.getRiskScore(),
                        asset.getStatus().name()));
            }
            for (Link link : network.getLinks()) {
                links.add(new Dtos.LinkDto(
                        link.getId(),
                        link.getSource().getId(),
                        link.getTarget().getId(),
                        link.getBaseCost(),
                        link.getBandwidth(),
                        link.getStatus().name()));
            }
            List<Map<String, Object>> teams = new ArrayList<>();
            for (AnalystTeam team : facade.listTeams()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", team.getName());
                row.put("capacity", team.getCapacity());
                teams.add(row);
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("assets", assets);
            body.put("links", links);
            body.put("teams", teams);
            return body;
        } finally {
            lock.unlock();
        }
    }

    private Dtos.StateDto buildState(String username, String role) {
        boolean running;
        boolean autoMode;
        int alertCount;
        int incidentCount;
        lock.lock();
        try {
            running = facade.isRunning();
            autoMode = facade.isAutoMode();
            List<Incident> incidents = facade.getIncidents();
            incidentCount = incidents.size();
            alertCount = broadcaster.getAlertCount();
        } finally {
            lock.unlock();
        }
        Map<String, String> user = new LinkedHashMap<>();
        user.put("username", username == null ? "" : username);
        user.put("role", role == null ? "" : role);
        return new Dtos.StateDto(running, autoMode, user, alertCount, incidentCount);
    }

    private String networkJson() {
        try {
            return mapper.writeValueAsString(networkBody());
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private String stateJson(String username, String role) {
        try {
            return mapper.writeValueAsString(buildState(username, role));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private String incidentsJson() {
        try {
            List<Dtos.IncidentDto> rows = new ArrayList<>();
            for (Incident incident : facade.getIncidents()) {
                rows.add(incidentDto(incident));
            }
            return mapper.writeValueAsString(rows);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private Dtos.IncidentDto incidentDto(Incident incident) {
        List<Dtos.AlertDto> alerts = new ArrayList<>();
        for (Alert alert : incident.getAlerts()) {
            alerts.add(alertDto(alert));
        }
        return new Dtos.IncidentDto(
                incident.getId(),
                incident.getSourceIp(),
                incident.getStatus().name(),
                incident.getOpenedAt() == null ? "" : incident.getOpenedAt().toString(),
                alerts);
    }

    private String alertJson(Alert alert) {
        try {
            return mapper.writeValueAsString(alertDto(alert));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static Dtos.AlertDto alertDto(Alert alert) {
        return new Dtos.AlertDto(
                alert.getId(),
                alert.getTimestamp().toString(),
                alert.getSeverity().name(),
                alert.getAttackType().name(),
                alert.getSourceIp(),
                alert.getTargetIp(),
                alert.getDetectorName(),
                alert.getDescription(),
                alert.isSimulated());
    }

    private boolean requiresCsrfToken(Context ctx) {
        HandlerType method = ctx.method();
        return method != HandlerType.GET && method != HandlerType.HEAD && method != HandlerType.OPTIONS;
    }

    private void enforceCsrf(Context ctx) {
        String cookie = ctx.cookie(CSRF_COOKIE);
        String header = ctx.header(CSRF_HEADER);
        if (cookie == null || header == null || !MessageDigest.isEqual(
                cookie.getBytes(StandardCharsets.UTF_8), header.getBytes(StandardCharsets.UTF_8))) {
            ctx.status(403).result("");
            ctx.skipRemainingHandlers();
        }
    }

    private void setCsrfCookie(Context ctx) {
        byte[] token = new byte[32];
        random.nextBytes(token);
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(token);
        String cookie = CSRF_COOKIE + "=" + value
                + "; Path=/; Max-Age=" + sessionMaxAgeSeconds + "; SameSite=Strict";
        if (secureCookie) {
            cookie += "; Secure";
        }
        ctx.res().addHeader("Set-Cookie", cookie);
    }

    private boolean rejectsContentType(Context ctx) {
        String raw = ctx.body();
        if (raw == null || raw.isBlank()) {
            return false;
        }
        String type = ctx.contentType();
        if (type == null || type.isBlank()) {
            return false;
        }
        if (!type.toLowerCase().contains(JSON_TYPE)) {
            ctx.status(415).result("");
            return true;
        }
        return false;
    }

    private void configuration(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            ctx.status(403).result("");
            return;
        }
        Map<String, Object> thresholds = new LinkedHashMap<>();
        for (String key : List.of(
                "risk.cap", "risk.compromiseThreshold", "incident.correlationWindowSeconds",
                "detection.cooldownSeconds", "detection.rate.windowSeconds", "detection.rate.maxFailures",
                "detection.portScan.windowSeconds", "detection.portScan.maxDistinctPorts",
                "detection.portScan.maxDistinctHosts", "detection.anomaly.zThreshold",
                "detection.anomaly.warmupCount", "alerts.buffer.max", "stream.network.intervalMillis")) {
            thresholds.put(key, config.getString(key, ""));
        }
        Map<String, Object> session = new LinkedHashMap<>();
        session.put("timeoutSeconds", sessionMaxAgeSeconds);
        session.put("csrfEnabled", csrfEnabled);
        session.put("loginMaxAttempts", loginThrottle.getMaxAttempts());
        session.put("loginWindowSeconds", loginThrottle.getWindowSeconds());
        List<Map<String, String>> accounts = new ArrayList<>();
        accounts.add(account("auth.defaultUsername", "Admin"));
        accounts.add(account("auth.analystUsername", "Analyst"));
        accounts.add(account("auth.viewerUsername", "Viewer"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("thresholds", thresholds);
        body.put("session", session);
        body.put("accounts", accounts);
        ctx.json(body);
    }

    private Map<String, String> account(String key, String role) {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("username", config.getString(key, ""));
        row.put("role", role);
        return row;
    }

    private JsonNode readJson(Context ctx) {
        try {
            String raw = ctx.body();
            if (raw == null || raw.isBlank()) {
                return mapper.createObjectNode();
            }
            return mapper.readTree(raw);
        } catch (JsonProcessingException ex) {
            return null;
        }
    }

    private static String text(JsonNode body, String field) {
        JsonNode node = body.get(field);
        return node == null || node.isNull() ? "" : node.asText();
    }

    private static String roleName(User user) {
        if (user instanceof Admin) {
            return "Admin";
        }
        if (user instanceof SecurityAnalyst) {
            return "Analyst";
        }
        if (user instanceof Viewer) {
            return "Viewer";
        }
        return "";
    }
}
