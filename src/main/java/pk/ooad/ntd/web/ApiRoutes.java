package pk.ooad.ntd.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HandlerType;
import pk.ooad.ntd.compliance.ComplianceService;
import pk.ooad.ntd.containment.ContainmentService;
import pk.ooad.ntd.correlation.SiemCorrelator;
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
import pk.ooad.ntd.flows.FlowQuery;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.forensics.EvidenceExporter;
import pk.ooad.ntd.ml.MlFlowScorer;
import pk.ooad.ntd.notify.NotificationService;
import pk.ooad.ntd.persistence.PersistenceException;
import pk.ooad.ntd.security.AuditLog;
import pk.ooad.ntd.service.Incident;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.util.ConfigManager;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeParseException;
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
            "/api/report", "/api/config", "/api/stream", "/api/flows",
            "/api/flows/history", "/api/persistence/status", "/api/audit", "/api/alert-quality",
            "/api/ml/status", "/api/correlation/status", "/api/containment",
            "/api/containment/release", "/api/notifications", "/api/compliance/summary",
            "/api/forensics/export");
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
    private final int flowApiMax;
    private final boolean csrfEnabled;
    private final int sessionMaxAgeSeconds;
    private final boolean secureCookie;

    public ApiRoutes(IncidentResponseFacade facade, StreamBroadcaster broadcaster, ReentrantLock lock) {
        this.facade = facade;
        this.broadcaster = broadcaster;
        this.lock = lock;
        this.alertBuffer = Math.max(1, config.getInt("alerts.buffer.max", 500));
        this.flowApiMax = Math.max(1, config.getInt("flow.api.max", 500));
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
        app.get("/api/flows", this::flows);
        app.get("/api/flows/history", this::flowHistory);
        app.get("/api/persistence/status", this::persistenceStatus);
        app.get("/api/audit", this::auditTrail);
        app.get("/api/alert-quality", this::alertQuality);
        app.get("/api/ml/status", this::mlStatus);
        app.get("/api/correlation/status", this::correlationStatus);
        app.get("/api/containment", this::containment);
        app.post("/api/containment", this::contain);
        app.post("/api/containment/release", this::releaseContainment);
        app.get("/api/notifications", this::notifications);
        app.get("/api/compliance/summary", this::complianceSummary);
        app.post("/api/forensics/export", this::exportEvidence);
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
            facade.getAuditLog().record(username, "auth.login", ctx.ip(),
                    AuditLog.Outcome.FAILED, "bad credentials");
            ctx.status(401).result("");
            return;
        } finally {
            lock.unlock();
        }
        loginThrottle.clear(throttleKey);
        rotateSession(ctx);
        String role = roleName(user);
        ctx.sessionAttribute("username", user.getUsername());
        ctx.sessionAttribute("role", role);
        ctx.sessionAttribute("canLaunchAttack", user.canLaunchAttack());
        ctx.sessionAttribute("canRunPlanner", user.canRunPlanner());
        setCsrfCookie(ctx);
        facade.getAuditLog().record(user.getUsername(), "auth.login", ctx.ip(),
                AuditLog.Outcome.ALLOWED, role);
        ctx.json(Map.of("username", user.getUsername(), "role", role));
    }

    /**
     * Drops the session the browser arrived with, so the identifier it held
     * before authenticating cannot be reused afterwards. That is session
     * fixation protection. The servlet interface on this stack has no
     * {@code changeSessionId}, so the old session is invalidated instead and a
     * fresh one is created by the attribute writes that follow.
     */
    private void rotateSession(Context ctx) {
        if (!Boolean.parseBoolean(config.getString("auth.session.rotateOnLogin", "true"))) {
            return;
        }
        try {
            jakarta.servlet.http.HttpSession existing = ctx.req().getSession(false);
            if (existing != null) {
                existing.invalidate();
            }
        } catch (IllegalStateException ignored) {
            // Already invalid, which is the outcome we wanted.
        }
    }

    private void logout(Context ctx) {
        facade.getAuditLog().record(actor(ctx), "auth.logout", ctx.ip(), AuditLog.Outcome.ALLOWED, "");
        if (ctx.req().getSession(false) != null) {
            ctx.req().getSession(false).invalidate();
        }
        ctx.status(200).result("");
    }

    private static String actor(Context ctx) {
        Object username = ctx.sessionAttribute("username");
        return username == null ? null : username.toString();
    }

    private void audit(Context ctx, String action, String target, AuditLog.Outcome outcome, String detail) {
        facade.getAuditLog().record(actor(ctx), action, target, outcome, detail);
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

    /**
     * Connection records for the flow table. Read-only, so every authenticated
     * role may call it. Malformed filters are rejected rather than ignored, so a
     * broken query never looks like an empty capture.
     */
    private void flows(Context ctx) {
        Integer port = null;
        Instant from = null;
        Instant to = null;
        int limit = flowApiMax;
        try {
            String rawPort = trimToNull(ctx.queryParam("port"));
            if (rawPort != null) {
                port = Integer.valueOf(rawPort);
                if (port < 0 || port > 65_535) {
                    ctx.status(400).result("");
                    return;
                }
            }
            String rawFrom = trimToNull(ctx.queryParam("from"));
            if (rawFrom != null) {
                from = parseInstant(rawFrom);
            }
            String rawTo = trimToNull(ctx.queryParam("to"));
            if (rawTo != null) {
                to = parseInstant(rawTo);
            }
            String rawLimit = trimToNull(ctx.queryParam("limit"));
            if (rawLimit != null) {
                limit = Integer.parseInt(rawLimit);
                if (limit < 0) {
                    ctx.status(400).result("");
                    return;
                }
            }
        } catch (NumberFormatException | DateTimeParseException ex) {
            ctx.status(400).result("");
            return;
        }
        FlowQuery query = new FlowQuery(trimToNull(ctx.queryParam("src")),
                trimToNull(ctx.queryParam("dst")), port, from, to, Math.min(limit, flowApiMax), true);
        List<Dtos.FlowDto> rows = new ArrayList<>();
        for (FlowRecord record : facade.getFlowRecorder().query(query)) {
            rows.add(flowDto(record));
        }
        ctx.json(rows);
    }

    /**
     * Flows that outlived the in-memory ring because they reached the durable
     * store. Answers 503 when persistence is switched off, because an empty list
     * would read like nothing was ever recorded.
     */
    private void flowHistory(Context ctx) {
        if (!facade.getPersistenceService().isEnabled()) {
            ctx.status(503).result("persistence is disabled");
            return;
        }
        int limit = flowApiMax;
        String raw = trimToNull(ctx.queryParam("limit"));
        if (raw != null) {
            try {
                limit = Integer.parseInt(raw);
            } catch (NumberFormatException ex) {
                ctx.status(400).result("");
                return;
            }
            if (limit < 0) {
                ctx.status(400).result("");
                return;
            }
        }
        try {
            List<Dtos.FlowDto> rows = new ArrayList<>();
            for (FlowRecord record : facade.getPersistenceService().storedFlows(Math.min(limit, flowApiMax))) {
                rows.add(flowDto(record));
            }
            ctx.json(rows);
        } catch (PersistenceException ex) {
            ctx.status(500).result("store unavailable");
        }
    }

    /** Store health for the admin console. Read only, but it names file paths. */
    private void persistenceStatus(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "store.status", "persistence", AuditLog.Outcome.DENIED, "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        ctx.json(facade.getPersistenceService().status());
    }

    /**
     * How much noise the quality gate is removing. Readable by every role,
     * because an analyst needs to know that a quiet feed may be a filtered one.
     */
    private void alertQuality(Context ctx) {
        var stats = facade.getAlertQualityGate().stats();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("dedupeEnabled", stats.dedupeEnabled());
        body.put("windowSeconds", facade.getAlertQualityGate().getWindowSeconds());
        body.put("minimumSeverity", stats.minimumSeverity());
        body.put("duplicates", stats.duplicates());
        body.put("belowFloor", stats.belowFloor());
        body.put("tracked", stats.tracked());
        ctx.json(body);
    }

    /**
     * Model state for the dashboard. Every role may read it, because "no
     * anomalies" from a cold model is not the same as a quiet network, and the
     * difference decides how the number on screen should be read.
     */
    private void mlStatus(Context ctx) {
        MlFlowScorer.Status status = facade.getMlFlowScorer().status();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", status.enabled());
        body.put("modelState", status.modelState());
        body.put("samples", status.samples());
        body.put("clusters", status.clusters());
        body.put("threshold", status.threshold());
        body.put("lastTrainedAt", status.lastTrainedAt());
        body.put("scored", status.scored());
        body.put("anomalies", status.anomalies());
        body.put("alerts", status.alerts());
        body.put("lastError", status.lastError());
        ctx.json(body);
    }

    /** Correlation activity, so a quiet feed can be told apart from a cold rule. */
    private void correlationStatus(Context ctx) {
        SiemCorrelator.Status status = facade.getSiemCorrelator().status();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", status.enabled());
        body.put("trackedSources", status.trackedSources());
        body.put("signals", status.signals());
        body.put("correlated", status.correlated());
        body.put("minSignals", status.minSignals());
        body.put("windowSeconds", status.windowSeconds());
        ctx.json(body);
    }

    /** Current blocks plus what enforcement has actually dropped. */
    private void containment(Context ctx) {
        ContainmentService service = facade.getContainmentService();
        ContainmentService.Status status = service.status();
        List<Map<String, Object>> rows = new ArrayList<>();
        for (ContainmentService.Action action : service.active()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("ip", action.ip());
            row.put("blockedAt", action.blockedAt().toString());
            row.put("expiresAt", action.expiresAt().toString());
            row.put("reason", action.reason());
            row.put("actor", action.actor());
            row.put("automatic", action.automatic());
            rows.add(row);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", status.enabled());
        body.put("auto", status.auto());
        body.put("enforce", status.enforce());
        body.put("blocked", rows);
        body.put("droppedEvents", status.droppedEvents());
        body.put("automaticActions", status.automaticActions());
        body.put("expiredActions", status.expiredActions());
        ctx.json(body);
    }

    private void contain(Context ctx) {
        if (!Boolean.TRUE.equals(ctx.sessionAttribute("canLaunchAttack"))) {
            audit(ctx, "containment.block", "containment", AuditLog.Outcome.DENIED,
                    "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        if (rejectsContentType(ctx)) {
            return;
        }
        JsonNode body = readJson(ctx);
        if (body == null) {
            ctx.status(400).result("");
            return;
        }
        String ip = trimToNull(text(body, "ip"));
        if (ip == null) {
            ctx.status(400).result("");
            return;
        }
        int minutes = body.path("minutes").asInt(30);
        if (minutes < 1) {
            ctx.status(400).result("");
            return;
        }
        try {
            ContainmentService.Action action = facade.getContainmentService()
                    .contain(ip, minutes, text(body, "reason"), actor(ctx));
            audit(ctx, "containment.block", ip, AuditLog.Outcome.ALLOWED,
                    minutes + " minutes: " + action.reason());
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("ip", action.ip());
            result.put("expiresAt", action.expiresAt().toString());
            ctx.json(result);
        } catch (IllegalStateException ex) {
            ctx.status(409).result(ex.getMessage() == null ? "containment unavailable" : ex.getMessage());
        } catch (IllegalArgumentException ex) {
            ctx.status(400).result("");
        }
    }

    private void releaseContainment(Context ctx) {
        if (!Boolean.TRUE.equals(ctx.sessionAttribute("canLaunchAttack"))) {
            audit(ctx, "containment.release", "containment", AuditLog.Outcome.DENIED,
                    "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        if (rejectsContentType(ctx)) {
            return;
        }
        JsonNode body = readJson(ctx);
        if (body == null) {
            ctx.status(400).result("");
            return;
        }
        String ip = trimToNull(text(body, "ip"));
        if (ip == null) {
            ctx.status(400).result("");
            return;
        }
        boolean removed = facade.getContainmentService().release(ip);
        audit(ctx, "containment.release", ip,
                removed ? AuditLog.Outcome.ALLOWED : AuditLog.Outcome.DENIED,
                removed ? "released" : "not blocked");
        ctx.status(removed ? 200 : 404).result("");
    }

    /** Recent notifications, newest first, together with delivery health. */
    private void notifications(Context ctx) {
        NotificationService service = facade.getNotificationService();
        NotificationService.Status status = service.status();
        int limit = Math.max(1, config.getInt("notifications.maxOutbox", 200));
        String raw = trimToNull(ctx.queryParam("limit"));
        if (raw != null) {
            try {
                limit = Integer.parseInt(raw);
            } catch (NumberFormatException ex) {
                ctx.status(400).result("");
                return;
            }
            if (limit < 0) {
                ctx.status(400).result("");
                return;
            }
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (NotificationService.Notification notification
                : service.recent(Math.min(limit, status.maxOutbox()))) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", notification.id());
            row.put("timestamp", notification.timestamp().toString());
            row.put("severity", notification.severity());
            row.put("attackType", notification.attackType());
            row.put("sourceIp", notification.sourceIp());
            row.put("targetIp", notification.targetIp());
            row.put("summary", notification.summary());
            row.put("channel", notification.channel());
            rows.add(row);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", status.enabled());
        body.put("minimumSeverity", status.minimumSeverity());
        body.put("webhookConfigured", status.webhookConfigured());
        body.put("recorded", status.recorded());
        body.put("webhookSent", status.webhookSent());
        body.put("webhookFailed", status.webhookFailed());
        body.put("dropped", status.dropped());
        body.put("lastError", status.lastError());
        body.put("notifications", rows);
        ctx.json(body);
    }

    /** Retention and capability state for the auditor, read from the components. */
    private void complianceSummary(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "compliance.read", "compliance", AuditLog.Outcome.DENIED,
                    "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        ComplianceService service = facade.getComplianceService();
        ComplianceService.Summary summary = service.summary();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("storeEnabled", summary.storeEnabled());
        body.put("databasePath", summary.databasePath());
        body.put("storedFlows", summary.storedFlows());
        body.put("storedAlerts", summary.storedAlerts());
        body.put("droppedRows", summary.droppedRows());
        body.put("retentionMinutes", summary.retentionMinutes());
        body.put("sweepMinutes", summary.sweepMinutes());
        body.put("retentionCutoff", service.retentionCutoff());
        body.put("auditCapacity", summary.auditCapacity());
        body.put("auditRecords", summary.auditRecords());
        body.put("auditDenied", summary.auditDenied());
        body.put("auditFailed", summary.auditFailed());
        body.put("notificationsEnabled", summary.notificationsEnabled());
        body.put("notificationBacklog", summary.notificationBacklog());
        body.put("containmentEnabled", summary.containmentEnabled());
        body.put("containedSources", summary.containedSources());
        body.put("forensicsEnabled", summary.forensicsEnabled());
        body.put("evidenceDirectory", summary.evidenceDirectory());
        ctx.json(body);
    }

    /**
     * Writes an evidence bundle and returns where it landed. Admin only, and
     * audited either way, because exporting records is itself a privileged act.
     */
    private void exportEvidence(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "evidence.export", "evidence", AuditLog.Outcome.DENIED,
                    "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        if (rejectsContentType(ctx)) {
            return;
        }
        try {
            EvidenceExporter.Bundle bundle = facade.exportEvidence(actor(ctx),
                    broadcaster.getRecentAlerts(alertBuffer));
            audit(ctx, "evidence.export", bundle.directory(), AuditLog.Outcome.ALLOWED,
                    bundle.files() + " files, " + bundle.bytes() + " bytes");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("directory", bundle.directory());
            body.put("createdAt", bundle.createdAt());
            body.put("files", bundle.files());
            body.put("bytes", bundle.bytes());
            body.put("manifestSha256", bundle.manifestSha256());
            ctx.json(body);
        } catch (IllegalStateException ex) {
            audit(ctx, "evidence.export", "evidence", AuditLog.Outcome.FAILED,
                    String.valueOf(ex.getMessage()));
            ctx.status(409).result(ex.getMessage() == null ? "export unavailable" : ex.getMessage());
        }
    }

    /** The audit trail itself. Admin only, because it names accounts and addresses. */
    private void auditTrail(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "audit.read", "audit", AuditLog.Outcome.DENIED, "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        int limit = Math.max(1, config.getInt("audit.api.max", 200));
        String raw = trimToNull(ctx.queryParam("limit"));
        if (raw != null) {
            try {
                limit = Integer.parseInt(raw);
            } catch (NumberFormatException ex) {
                ctx.status(400).result("");
                return;
            }
            if (limit < 0) {
                ctx.status(400).result("");
                return;
            }
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (AuditLog.Entry entry : facade.getAuditLog().recent(limit)) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sequence", entry.sequence());
            row.put("timestamp", entry.timestamp() == null ? null : entry.timestamp().toString());
            row.put("actor", entry.actor());
            row.put("action", entry.action());
            row.put("target", entry.target());
            row.put("outcome", entry.outcome());
            row.put("detail", entry.detail());
            rows.add(row);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("entries", rows);
        body.put("denied", facade.getAuditLog().deniedCount());
        body.put("failed", facade.getAuditLog().failedCount());
        body.put("capacity", facade.getAuditLog().getMaxRecords());
        ctx.json(body);
    }

    private static Instant parseInstant(String raw) {
        if (raw.chars().allMatch(Character::isDigit)) {
            return Instant.ofEpochMilli(Long.parseLong(raw));
        }
        return Instant.parse(raw);
    }

    private static String trimToNull(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static Dtos.FlowDto flowDto(FlowRecord flow) {
        return new Dtos.FlowDto(flow.id(), flow.srcIp(), flow.dstIp(), flow.srcPort(), flow.dstPort(),
                flow.protocol(), flow.bytesOut(), flow.bytesIn(), flow.packets(),
                flow.startTime() == null ? "" : flow.startTime().toString(),
                flow.endTime() == null ? "" : flow.endTime().toString(), flow.durationMs(),
                flow.flags(), flow.label(), flow.simulated(), flow.ended());
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
