package pk.ooad.ntd.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HandlerType;
import pk.ooad.ntd.compliance.ComplianceService;
import pk.ooad.ntd.containment.ContainmentSafeguards;
import pk.ooad.ntd.containment.ContainmentService;
import pk.ooad.ntd.correlation.SiemCorrelator;
import pk.ooad.ntd.detection.AlertQualityGate;
import pk.ooad.ntd.detection.DetectionEngine;
import pk.ooad.ntd.detection.SuppressionRules;
import pk.ooad.ntd.domain.Admin;
import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertStatus;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.MitigationTask;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.ResponsePlan;
import pk.ooad.ntd.domain.SecurityAnalyst;
import pk.ooad.ntd.domain.User;
import pk.ooad.ntd.domain.Viewer;
import pk.ooad.ntd.export.ExportService;
import pk.ooad.ntd.flows.FlowQuery;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.forensics.EvidenceExporter;
import pk.ooad.ntd.imports.ImportService;
import pk.ooad.ntd.ml.EvaluationService;
import pk.ooad.ntd.ml.MlFlowScorer;
import pk.ooad.ntd.notify.NotificationService;
import pk.ooad.ntd.persistence.AlertRecord;
import pk.ooad.ntd.persistence.PersistenceException;
import pk.ooad.ntd.persistence.PersistenceService;
import pk.ooad.ntd.persistence.PersistenceStatus;
import pk.ooad.ntd.security.AuditLog;
import pk.ooad.ntd.security.SecurityPolicy;
import pk.ooad.ntd.service.Incident;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.service.IntelService;
import pk.ooad.ntd.simulation.ScenarioService;
import pk.ooad.ntd.simulation.SimulationNoise;
import pk.ooad.ntd.util.ConfigManager;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

public class ApiRoutes {
    private static final Set<String> API_PATHS = Set.of(
            "/api/login", "/api/logout", "/api/state", "/api/network",
            "/api/sim/start", "/api/sim/stop", "/api/sim/reset", "/api/sim/auto",
            "/api/attacks", "/api/alerts", "/api/events", "/api/incidents", "/api/response/run",
            "/api/report", "/api/config", "/api/stream", "/api/flows",
            "/api/flows/history", "/api/persistence/status", "/api/audit", "/api/alert-quality",
            "/api/ml/status", "/api/ml/evaluation", "/api/ml/evaluate", "/api/correlation/status", "/api/containment",
            "/api/containment/mode", "/api/containment/release", "/api/notifications",
            "/api/notifications/test", "/api/notifications/control", "/api/compliance/summary",
            "/api/forensics/export", "/api/import/zeek", "/api/import/status", "/api/import/sample",
            "/api/suppression/rules", "/api/retention", "/api/demo", "/api/metrics",
            "/api/intel/status", "/api/intel/reload", "/api/scenarios");
    private static final Set<String> API_PREFIXES = Set.of(
            "/api/alerts/", "/api/incidents/", "/api/suppression/rules/", "/api/export/");
    private static final String CSRF_COOKIE = "csrf";
    private static final String CSRF_HEADER = "X-CSRF-Token";
    private static final String JSON_TYPE = "application/json";

    private final IncidentResponseFacade facade;
    private final StreamBroadcaster broadcaster;
    private final ReentrantLock lock;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ConfigManager config = ConfigManager.getInstance();
    private final LoginThrottle loginThrottle = new LoginThrottle();
    private final LoginThrottle reauthThrottle = new LoginThrottle(
            ConfigManager.getInstance().getInt("auth.reauth.maxAttempts", 5),
            ConfigManager.getInstance().getInt("auth.reauth.windowSeconds", 300));
    private final SecureRandom random = new SecureRandom();
    private final int alertBuffer;
    private final int flowApiMax;
    private final int exportMaxRows;
    private final int maxBodyBytes;
    private final boolean reauthEnabled;
    private final int reauthFreshSeconds;
    private final ExportService exportService = new ExportService();
    private final boolean csrfEnabled;
    private final int sessionMaxAgeSeconds;
    private final int absoluteSessionSeconds;
    private final boolean secureCookie;
    private final Instant startedAt = Instant.now();

    public ApiRoutes(IncidentResponseFacade facade, StreamBroadcaster broadcaster, ReentrantLock lock) {
        this.facade = facade;
        this.broadcaster = broadcaster;
        this.lock = lock;
        this.alertBuffer = Math.max(1, config.getInt("alerts.buffer.max", 500));
        this.flowApiMax = Math.max(1, config.getInt("flow.api.max", 500));
        this.exportMaxRows = Math.max(1, config.getInt("export.maxRows", 5000));
        this.maxBodyBytes = Math.max(1024, config.getInt("http.maxBodyBytes", 8_388_608));
        this.reauthEnabled = Boolean.parseBoolean(config.getString("auth.reauth.enabled", "true"));
        this.reauthFreshSeconds = Math.max(0, config.getInt("auth.reauth.freshSeconds", 0));
        this.csrfEnabled = Boolean.parseBoolean(config.getString("auth.csrf.enabled", "true"));
        this.sessionMaxAgeSeconds = Math.max(60, config.getInt("auth.session.timeoutSeconds", 28800));
        this.absoluteSessionSeconds = Math.max(0, config.getInt("auth.session.absoluteTimeoutSeconds", 43200));
        this.secureCookie = Boolean.parseBoolean(config.getString("auth.session.secureCookie", "false"));
        broadcaster.setEncoders(this::alertJson, this::networkJson, this::stateJson, this::incidentsJson);
    }

    public void register(Javalin app) {
        app.before(ctx -> {
            if (!ctx.path().startsWith("/api")) {
                return;
            }
            if (!API_PATHS.contains(ctx.path())) {
                if (!allowedByPrefix(ctx.path())) {
                    ctx.status(404).result("");
                    ctx.skipRemainingHandlers();
                    return;
                }
            }
            if ("/api/login".equals(ctx.path()) && ctx.method() == HandlerType.POST) {
                return;
            }
            if ("/api/demo".equals(ctx.path()) && ctx.method() == HandlerType.GET) {
                return;
            }
            if (ctx.sessionAttribute("username") == null) {
                ctx.status(401).result("");
                ctx.skipRemainingHandlers();
                return;
            }
            if (expiredSession(ctx)) {
                ctx.status(401).result("");
                ctx.skipRemainingHandlers();
                return;
            }
            if (csrfEnabled && requiresCsrfToken(ctx)) {
                enforceCsrf(ctx);
            }
        });

        app.post("/api/login", this::login);
        app.get("/api/demo", this::demo);
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
        app.get("/api/events", this::events);
        app.post("/api/alerts/{id}/status", this::alertStatus);
        app.get("/api/suppression/rules", this::suppressionRules);
        app.post("/api/suppression/rules", this::addSuppressionRule);
        app.delete("/api/suppression/rules/{id}", this::removeSuppressionRule);
        app.get("/api/flows", this::flows);
        app.get("/api/flows/history", this::flowHistory);
        app.get("/api/persistence/status", this::persistenceStatus);
        app.get("/api/audit", this::auditTrail);
        app.get("/api/alert-quality", this::alertQuality);
        app.get("/api/metrics", this::metrics);
        app.get("/api/intel/status", this::intelStatus);
        app.post("/api/intel/reload", this::reloadIntel);
        app.post("/api/scenarios", this::scenario);
        app.get("/api/ml/status", this::mlStatus);
        app.get("/api/ml/evaluation", this::mlEvaluation);
        app.post("/api/ml/evaluate", this::evaluateModel);
        app.get("/api/correlation/status", this::correlationStatus);
        app.get("/api/containment", this::containment);
        app.post("/api/containment", this::contain);
        app.post("/api/containment/mode", this::containmentMode);
        app.post("/api/containment/release", this::releaseContainment);
        app.get("/api/notifications", this::notifications);
        app.post("/api/notifications/test", this::notificationTest);
        app.post("/api/notifications/control", this::notificationControl);
        app.get("/api/compliance/summary", this::complianceSummary);
        app.post("/api/forensics/export", this::exportEvidence);
        app.post("/api/import/zeek", this::importZeek);
        app.get("/api/import/status", this::importStatus);
        app.get("/api/import/sample", this::importSample);
        app.get("/api/incidents", this::incidents);
        app.get("/api/incidents/{id}", this::incidentDetail);
        app.get("/api/incidents/{id}/bundle", this::incidentBundle);
        app.get("/api/export/{kind}", this::exportTable);
        app.post("/api/retention", this::setRetention);
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
        String accountKey = "account:" + username;
        String addressKey = "address:" + ctx.ip();
        if (!loginThrottle.allowed(accountKey, addressKey)) {
            ctx.header("Retry-After", String.valueOf(loginThrottle.retryAfterSeconds(accountKey, addressKey)));
            ctx.status(429).result("");
            return;
        }
        User user;
        lock.lock();
        try {
            user = facade.login(username, password);
        } catch (IllegalArgumentException ex) {
            loginThrottle.recordFailure(accountKey, addressKey);
            facade.getAuditLog().record(username, "auth.login", ctx.ip(),
                    AuditLog.Outcome.FAILED, "bad credentials");
            ctx.status(401).result("");
            return;
        } finally {
            lock.unlock();
        }
        loginThrottle.clear(accountKey, addressKey);
        rotateSession(ctx);
        String role = roleName(user);
        ctx.sessionAttribute("username", user.getUsername());
        ctx.sessionAttribute("role", role);
        ctx.sessionAttribute("canLaunchAttack", user.canLaunchAttack());
        ctx.sessionAttribute("canRunPlanner", user.canRunPlanner());
        ctx.sessionAttribute("loginAt", System.currentTimeMillis());
        setCsrfCookie(ctx);
        facade.getAuditLog().record(user.getUsername(), "auth.login", ctx.ip(),
                AuditLog.Outcome.ALLOWED, role);
        ctx.json(Map.of("username", user.getUsername(), "role", role));
    }

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
        }
    }

    private boolean expiredSession(Context ctx) {
        if (absoluteSessionSeconds <= 0) {
            return false;
        }
        Object started = ctx.sessionAttribute("loginAt");
        if (!(started instanceof Long at)) {
            ctx.sessionAttribute("loginAt", System.currentTimeMillis());
            return false;
        }
        if (System.currentTimeMillis() - at <= absoluteSessionSeconds * 1000L) {
            return false;
        }
        facade.getAuditLog().record(actor(ctx), "auth.expired", ctx.ip(), AuditLog.Outcome.DENIED,
                "absolute session timeout");
        try {
            if (ctx.req().getSession(false) != null) {
                ctx.req().getSession(false).invalidate();
            }
        } catch (IllegalStateException ignored) {
        }
        return true;
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

    private void demo(Context ctx) {
        SecurityPolicy policy = facade.getSecurityPolicy();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("demoMode", policy.demoMode());
        if (policy.demoMode()) {
            body.put("notice", "Demo mode: traffic is simulated and the shipped accounts are enabled.");
            List<Map<String, String>> accounts = new ArrayList<>();
            accounts.add(demoAccount("auth.defaultUsername", "Admin"));
            accounts.add(demoAccount("auth.analystUsername", "Analyst"));
            accounts.add(demoAccount("auth.viewerUsername", "Viewer"));
            body.put("accounts", accounts);
        }
        ctx.json(body);
    }

    private Map<String, String> demoAccount(String key, String role) {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("username", config.getString(key, ""));
        row.put("role", role);
        row.put("password", role.toLowerCase(Locale.ROOT));
        return row;
    }

    private int reauthStatus(Context ctx, String password) {
        if (!reauthEnabled) {
            return 0;
        }
        Object stamp = ctx.sessionAttribute("reauthAt");
        if (reauthFreshSeconds > 0 && stamp instanceof Long at
                && System.currentTimeMillis() - at <= reauthFreshSeconds * 1000L) {
            return 0;
        }
        String key = "reauth:" + actor(ctx) + "|" + ctx.ip();
        if (!reauthThrottle.allowed(key)) {
            ctx.header("Retry-After", String.valueOf(reauthThrottle.retryAfterSeconds(key)));
            return 429;
        }
        if (password == null || password.isEmpty() || !facade.verifyPassword(actor(ctx), password)) {
            reauthThrottle.recordFailure(key);
            return 401;
        }
        reauthThrottle.clear(key);
        ctx.sessionAttribute("reauthAt", System.currentTimeMillis());
        return 0;
    }

    private static String reauthDetail(int status) {
        return status == 429 ? "re-entry throttled" : "password re-entry failed";
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
        AlertFilter filter = alertFilter(ctx, alertBuffer, false);
        if (filter == null) {
            ctx.status(400).result("");
            return;
        }
        List<Dtos.AlertDto> alerts = new ArrayList<>();
        for (Alert alert : selectAlerts(filter)) {
            alerts.add(alertDto(alert));
        }
        ctx.json(alerts);
    }

    private void events(Context ctx) {
        AlertFilter filter = alertFilter(ctx, 50, true);
        if (filter == null) {
            ctx.status(400).result("");
            return;
        }
        List<Alert> matched = selectAlerts(filter);
        List<Dtos.AlertDto> rows = new ArrayList<>();
        for (int index = filter.offset(); index < matched.size() && rows.size() < filter.limit(); index++) {
            rows.add(alertDto(matched.get(index)));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("total", matched.size());
        body.put("offset", filter.offset());
        body.put("limit", filter.limit());
        body.put("events", rows);
        ctx.json(body);
    }

    private List<Alert> selectAlerts(AlertFilter filter) {
        List<Alert> matched = new ArrayList<>();
        for (Alert alert : alertCandidates()) {
            if (matches(alert, filter)) {
                matched.add(alert);
            }
        }
        return matched;
    }

    private List<Alert> alertCandidates() {
        Map<String, Alert> byId = new LinkedHashMap<>();
        for (Alert alert : broadcaster.getRecentAlerts(alertBuffer)) {
            byId.put(alert.getId(), alert);
        }
        PersistenceService store = facade.getPersistenceService();
        if (store != null && store.isEnabled()) {
            for (AlertRecord record : store.storedAlerts(alertBuffer)) {
                Alert restored = record.toAlert();
                if (restored != null) {
                    byId.putIfAbsent(restored.getId(), restored);
                }
            }
        }
        List<Alert> out = new ArrayList<>(byId.values());
        out.sort((left, right) -> {
            Instant a = left.getTimestamp();
            Instant b = right.getTimestamp();
            if (a == null && b == null) {
                return 0;
            }
            if (a == null) {
                return 1;
            }
            if (b == null) {
                return -1;
            }
            return b.compareTo(a);
        });
        return out;
    }

    private static boolean matches(Alert alert, AlertFilter filter) {
        if (alert == null) {
            return false;
        }
        if (filter.severity() != null
                && (alert.getSeverity() == null || !filter.severity().equals(alert.getSeverity().name()))) {
            return false;
        }
        if (filter.attackType() != null
                && (alert.getAttackType() == null || !filter.attackType().equals(alert.getAttackType().name()))) {
            return false;
        }
        if (filter.detector() != null && !contains(alert.getDetectorName(), filter.detector())) {
            return false;
        }
        if (filter.sourceIp() != null && !contains(alert.getSourceIp(), filter.sourceIp())) {
            return false;
        }
        if (filter.targetIp() != null && !contains(alert.getTargetIp(), filter.targetIp())) {
            return false;
        }
        Instant at = alert.getTimestamp();
        if (filter.from() != null && (at == null || at.isBefore(filter.from()))) {
            return false;
        }
        if (filter.to() != null && (at == null || at.isAfter(filter.to()))) {
            return false;
        }
        if (filter.simulated() != null && filter.simulated() != alert.isSimulated()) {
            return false;
        }
        return filter.text() == null || haystack(alert).contains(filter.text());
    }

    private static boolean contains(String value, String needle) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(needle);
    }

    private static String haystack(Alert alert) {
        StringBuilder text = new StringBuilder();
        text.append(alert.getId()).append(' ').append(alert.getDescription()).append(' ')
                .append(alert.getDetectorName()).append(' ').append(alert.getSourceIp()).append(' ')
                .append(alert.getTargetIp()).append(' ').append(alert.getAttackType()).append(' ')
                .append(alert.getSeverity()).append(' ').append(alert.getStatus()).append(' ')
                .append(alert.isSimulated() ? "simulated import" : "live");
        return text.toString().toLowerCase(Locale.ROOT);
    }

    private AlertFilter alertFilter(Context ctx, int defaultLimit, boolean paged) {
        try {
            int requested = number(ctx, "limit", defaultLimit);
            if (requested < 0) {
                return null;
            }
            int limit = Math.min(Math.max(1, requested), alertBuffer);
            int offset = paged ? Math.max(0, number(ctx, "offset", 0)) : 0;
            String severity = upper(ctx.queryParam("severity"));
            if (severity != null && !Set.of("LOW", "HIGH", "CRITICAL").contains(severity)) {
                return null;
            }
            String attackType = upper(ctx.queryParam("attackType"));
            if (attackType != null) {
                AttackType.valueOf(attackType);
            }
            Instant from = instant(ctx.queryParam("from"));
            Instant to = instant(ctx.queryParam("to"));
            if (from != null && to != null && to.isBefore(from)) {
                return null;
            }
            return new AlertFilter(text(ctx), severity, attackType,
                    lower(ctx.queryParam("detector")), trimToNull(ctx.queryParam("source")),
                    trimToNull(ctx.queryParam("target")), flag(ctx.queryParam("simulated")),
                    from, to, limit, offset);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static String text(Context ctx) {
        String value = lower(ctx.queryParam("q"));
        return value == null ? lower(ctx.queryParam("text")) : value;
    }

    private static int number(Context ctx, String name, int fallback) {
        String raw = trimToNull(ctx.queryParam(name));
        return raw == null ? fallback : Integer.parseInt(raw);
    }

    private static Instant instant(String raw) {
        String value = trimToNull(raw);
        if (value == null) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ex) {
            throw new IllegalArgumentException("not an instant: " + value, ex);
        }
    }

    private static Boolean flag(String raw) {
        String value = trimToNull(raw);
        if (value == null) {
            return null;
        }
        if ("true".equalsIgnoreCase(value)) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(value)) {
            return Boolean.FALSE;
        }
        throw new IllegalArgumentException("not a flag: " + value);
    }

    private static String upper(String raw) {
        String value = trimToNull(raw);
        return value == null ? null : value.toUpperCase(Locale.ROOT);
    }

    private static String lower(String raw) {
        String value = trimToNull(raw);
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    private record AlertFilter(String text, String severity, String attackType, String detector,
                               String sourceIp, String targetIp, Boolean simulated,
                               Instant from, Instant to, int limit, int offset) {
    }

    private void alertStatus(Context ctx) {
        String actor = ctx.sessionAttribute("username");
        if (!canControlSim(ctx)) {
            facade.getAuditLog().record(actor, "alert.status", ctx.pathParam("id"),
                    AuditLog.Outcome.DENIED, "role cannot triage");
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
        AlertStatus next;
        try {
            next = AlertStatus.valueOf(body.path("status").asText("").trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            ctx.status(400).result("");
            return;
        }
        String id = ctx.pathParam("id");
        IncidentResponseFacade.StatusChange change;
        lock.lock();
        try {
            change = facade.moveAlertStatus(id, next);
        } finally {
            lock.unlock();
        }
        if (change == null) {
            ctx.status(404).result("");
            return;
        }
        if (!change.moved()) {
            facade.getAuditLog().record(actor, "alert.status", id, AuditLog.Outcome.DENIED,
                    change.previous() + " -> " + next);
            ctx.status(409).json(Map.of(
                    "error", "That move is not in the status table",
                    "status", change.previous().name()));
            return;
        }
        facade.getAuditLog().record(actor, "alert.status", id, AuditLog.Outcome.ALLOWED,
                change.previous() + " -> " + next);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("alert", alertDto(change.alert()));
        if (next == AlertStatus.FALSE_POSITIVE) {
            out.put("proposedRule", proposedRule(change.alert()));
        }
        ctx.json(out);
    }

    private void suppressionRules(Context ctx) {
        SuppressionRules rules = facade.getSuppressionRules();
        List<Map<String, Object>> rows = new ArrayList<>();
        for (SuppressionRules.Rule rule : rules.rules()) {
            rows.add(ruleBody(rule));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", rules.isEnabled());
        body.put("file", rules.file() == null ? "" : rules.file().toString());
        body.put("count", rows.size());
        body.put("rules", rows);
        ctx.json(body);
    }

    private void addSuppressionRule(Context ctx) {
        String actor = ctx.sessionAttribute("username");
        if (!canControlSim(ctx)) {
            facade.getAuditLog().record(actor, "alert.suppress.add", ctx.ip(),
                    AuditLog.Outcome.DENIED, "role cannot change suppression");
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
        SuppressionRules.Rule requested = new SuppressionRules.Rule(
                body.path("id").asText(""),
                body.path("detector").asText(""),
                body.path("attackType").asText(""),
                body.path("sourceIp").asText(""),
                body.path("targetIp").asText(""),
                body.path("maxSeverity").asText(""),
                body.path("note").asText(""),
                "", "",
                !body.has("enabled") || body.path("enabled").asBoolean(true));
        try {
            SuppressionRules.Rule stored = facade.getSuppressionRules().add(requested, actor);
            facade.getAuditLog().record(actor, "alert.suppress.add", stored.id(),
                    AuditLog.Outcome.ALLOWED, stored.describe());
            ctx.status(201).json(ruleBody(stored));
        } catch (IllegalArgumentException ex) {
            facade.getAuditLog().record(actor, "alert.suppress.add", requested.describe(),
                    AuditLog.Outcome.DENIED, ex.getMessage());
            ctx.status(400).json(Map.of("error", ex.getMessage()));
        }
    }

    private void removeSuppressionRule(Context ctx) {
        String actor = ctx.sessionAttribute("username");
        if (!canControlSim(ctx)) {
            facade.getAuditLog().record(actor, "alert.suppress.remove", ctx.pathParam("id"),
                    AuditLog.Outcome.DENIED, "role cannot change suppression");
            ctx.status(403).result("");
            return;
        }
        SuppressionRules.Rule removed = facade.getSuppressionRules().remove(ctx.pathParam("id"));
        if (removed == null) {
            facade.getAuditLog().record(actor, "alert.suppress.remove", ctx.pathParam("id"),
                    AuditLog.Outcome.DENIED, "no such rule");
            ctx.status(404).result("");
            return;
        }
        facade.getAuditLog().record(actor, "alert.suppress.remove", removed.id(),
                AuditLog.Outcome.ALLOWED, removed.describe());
        ctx.status(204).result("");
    }

    private static Map<String, Object> ruleBody(SuppressionRules.Rule rule) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", rule.id());
        row.put("detector", rule.detector());
        row.put("attackType", rule.attackType());
        row.put("sourceIp", rule.sourceIp());
        row.put("targetIp", rule.targetIp());
        row.put("maxSeverity", rule.maxSeverity());
        row.put("note", rule.note());
        row.put("createdBy", rule.createdBy());
        row.put("createdAt", rule.createdAt());
        row.put("enabled", rule.enabled());
        row.put("describe", rule.describe());
        return row;
    }

    private static Map<String, Object> proposedRule(Alert alert) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("detector", alert.getDetectorName());
        rule.put("attackType", alert.getAttackType() == null ? "" : alert.getAttackType().name());
        rule.put("sourceIp", alert.getSourceIp());
        rule.put("targetIp", alert.getTargetIp());
        rule.put("maxSeverity", alert.getSeverity() == null ? "" : alert.getSeverity().name());
        rule.put("note", "Proposed from a false positive on alert " + alert.getId());
        rule.put("enabled", true);
        return rule;
    }

    private static boolean allowedByPrefix(String path) {
        for (String prefix : API_PREFIXES) {
            if (!path.startsWith(prefix)) {
                continue;
            }
            String rest = path.substring(prefix.length());
            if (rest.isEmpty() || rest.contains("..") || rest.contains("\\")) {
                continue;
            }
            boolean clean = true;
            for (String segment : rest.split("/", -1)) {
                if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                    clean = false;
                    break;
                }
            }
            if (clean) {
                return true;
            }
        }
        return false;
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

    private void incidentDetail(Context ctx) {
        String id = ctx.pathParam("id");
        Incident found = null;
        lock.lock();
        try {
            for (Incident incident : facade.getIncidents()) {
                if (incident.getId().equals(id)) {
                    found = incident;
                    break;
                }
            }
        } finally {
            lock.unlock();
        }
        if (found == null) {
            ctx.status(404).result("");
            return;
        }
        ctx.json(incidentDetailBody(found));
    }

    private Map<String, Object> incidentDetailBody(Incident incident) {
        List<Alert> alerts = new ArrayList<>(incident.getAlerts());
        alerts.sort((left, right) -> {
            Instant a = left.getTimestamp();
            Instant b = right.getTimestamp();
            if (a == null && b == null) {
                return 0;
            }
            if (a == null) {
                return -1;
            }
            if (b == null) {
                return 1;
            }
            return a.compareTo(b);
        });
        List<Map<String, Object>> timeline = new ArrayList<>();
        Set<String> detectors = new LinkedHashSet<>();
        Set<AttackType> types = new LinkedHashSet<>();
        for (Alert alert : alerts) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("at", alert.getTimestamp() == null ? null : alert.getTimestamp().toString());
            boolean escalation = SiemCorrelator.DETECTOR_NAME.equals(alert.getDetectorName());
            entry.put("kind", escalation ? "escalation" : "alert");
            entry.put("title", escalation
                    ? "Escalation: " + alert.getDescription()
                    : alert.getDetectorName() + " raised " + alert.getAttackType());
            entry.put("detail", alert.getDescription());
            entry.put("severity", alert.getSeverity() == null ? null : alert.getSeverity().name());
            entry.put("detector", alert.getDetectorName());
            entry.put("attackType", alert.getAttackType() == null ? null : alert.getAttackType().name());
            entry.put("sourceIp", alert.getSourceIp());
            entry.put("targetIp", alert.getTargetIp());
            entry.put("alertId", alert.getId());
            entry.put("occurrences", alert.getOccurrences());
            entry.put("simulated", alert.isSimulated());
            timeline.add(entry);
            if (alert.getDetectorName() != null) {
                detectors.add(alert.getDetectorName());
            }
            if (alert.getAttackType() != null) {
                types.add(alert.getAttackType());
            }
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", incident.getId());
        body.put("sourceIp", incident.getSourceIp());
        body.put("openedAt", incident.getOpenedAt() == null ? null : incident.getOpenedAt().toString());
        body.put("status", incident.getStatus().name());
        body.put("highestSeverity", incident.getHighestSeverity() == null
                ? null : incident.getHighestSeverity().name());
        body.put("alertCount", alerts.size());
        body.put("firstSeen", alerts.isEmpty() || alerts.get(0).getTimestamp() == null
                ? null : alerts.get(0).getTimestamp().toString());
        body.put("lastSeen", alerts.isEmpty() || alerts.get(alerts.size() - 1).getTimestamp() == null
                ? null : alerts.get(alerts.size() - 1).getTimestamp().toString());
        body.put("detectors", new ArrayList<>(detectors));
        body.put("attackTypes", types.stream().map(Enum::name).toList());
        body.put("timeline", timeline);
        body.put("alerts", incidentDto(incident).alerts());
        return body;
    }

    private void incidentBundle(Context ctx) {
        Incident incident = findIncident(ctx.pathParam("id"));
        if (incident == null) {
            ctx.status(404).result("");
            return;
        }
        Map<String, Object> detail = incidentDetailBody(incident);
        Object timeline = detail.get("timeline");
        int count = timeline instanceof List<?> rows ? rows.size() : 0;
        Map<String, Object> manifest = exportService.manifest("incident", detail, count);
        Map<String, Object> body = new LinkedHashMap<>(detail);
        body.put("manifest", manifest);
        ctx.header("X-Manifest-SHA256", String.valueOf(manifest.get("sha256")));
        audit(ctx, "incident.bundle", incident.getId(), AuditLog.Outcome.ALLOWED,
                "manifest " + manifest.get("sha256"));
        ctx.json(body);
    }

    private Incident findIncident(String id) {
        if (id == null || id.isBlank()) {
            return null;
        }
        lock.lock();
        try {
            for (Incident incident : facade.getIncidents()) {
                if (id.equals(incident.getId())) {
                    return incident;
                }
            }
        } finally {
            lock.unlock();
        }
        return null;
    }

    private void exportTable(Context ctx) {
        String kind = ctx.pathParam("kind");
        String requested = trimToNull(ctx.queryParam("format"));
        String format = requested == null ? "csv" : requested.toLowerCase(Locale.ROOT);
        if (!format.equals("csv") && !format.equals("json")) {
            ctx.status(400).result("");
            return;
        }
        ExportService.Table table;
        try {
            table = exportTableFor(kind);
        } catch (IllegalArgumentException ex) {
            ctx.status(400).result(ex.getMessage() == null ? "" : ex.getMessage());
            return;
        }
        ExportService.Rendered rendered = exportService.render(table, format);
        ctx.header("X-Content-SHA256", rendered.sha256());
        ctx.header("Content-Disposition", "attachment; filename=\"ntd-" + table.kind() + "-"
                + Instant.now().toEpochMilli() + "." + format + "\"");
        ctx.res().setContentType(rendered.contentType());
        audit(ctx, "export." + table.kind(), format, AuditLog.Outcome.ALLOWED,
                rendered.count() + " rows, sha256 " + rendered.sha256());
        ctx.result(rendered.body());
    }

    private ExportService.Table exportTableFor(String kind) {
        String requested = kind == null ? "" : kind.toLowerCase(Locale.ROOT);
        switch (requested) {
            case "alerts":
                return alertExport(alertCandidates());
            case "events":
                return eventExport(alertCandidates());
            case "incidents":
                return incidentExport();
            case "flows":
                return flowExport();
            default:
                throw new IllegalArgumentException("unknown export kind; use alerts, events, incidents or flows");
        }
    }

    private ExportService.Table alertExport(List<Alert> alerts) {
        List<List<String>> rows = new ArrayList<>();
        for (Alert alert : cap(alerts)) {
            rows.add(List.of(
                    cell(alert.getId()),
                    cell(alert.getTimestamp()),
                    cell(alert.getSeverity()),
                    cell(alert.getAttackType()),
                    cell(alert.getSourceIp()),
                    cell(alert.getTargetIp()),
                    cell(alert.getDetectorName()),
                    cell(alert.getDescription()),
                    cell(alert.getStatus()),
                    String.valueOf(alert.getOccurrences()),
                    String.valueOf(alert.isSimulated())));
        }
        return new ExportService.Table("alerts",
                List.of("id", "timestamp", "severity", "attackType", "sourceIp", "targetIp",
                        "detector", "description", "status", "occurrences", "simulated"),
                rows);
    }

    private ExportService.Table eventExport(List<Alert> alerts) {
        List<List<String>> rows = new ArrayList<>();
        for (Alert alert : cap(alerts)) {
            boolean escalation = SiemCorrelator.DETECTOR_NAME.equals(alert.getDetectorName());
            rows.add(List.of(
                    cell(alert.getId()),
                    cell(alert.getTimestamp()),
                    escalation ? "escalation" : "alert",
                    cell(alert.getDetectorName()),
                    cell(alert.getAttackType()),
                    cell(alert.getSeverity()),
                    cell(alert.getSourceIp()),
                    cell(alert.getTargetIp()),
                    cell(alert.getDescription()),
                    cell(alert.getStatus()),
                    String.valueOf(alert.getOccurrences())));
        }
        return new ExportService.Table("events",
                List.of("id", "at", "kind", "detector", "attackType", "severity", "sourceIp",
                        "targetIp", "description", "status", "occurrences"),
                rows);
    }

    private ExportService.Table incidentExport() {
        List<Incident> incidents;
        lock.lock();
        try {
            incidents = new ArrayList<>(facade.getIncidents());
        } finally {
            lock.unlock();
        }
        List<List<String>> rows = new ArrayList<>();
        for (Incident incident : incidents) {
            if (rows.size() >= exportMaxRows) {
                break;
            }
            List<Alert> owned = new ArrayList<>(incident.getAlerts());
            List<String> alertIds = new ArrayList<>();
            for (Alert alert : owned) {
                alertIds.add(alert.getId());
            }
            rows.add(List.of(
                    cell(incident.getId()),
                    cell(incident.getOpenedAt()),
                    cell(incident.getSourceIp()),
                    cell(incident.getStatus()),
                    cell(incident.getHighestSeverity()),
                    String.valueOf(owned.size()),
                    cell(String.join(";", alertIds))));
        }
        return new ExportService.Table("incidents",
                List.of("id", "openedAt", "sourceIp", "status", "highestSeverity", "alertCount", "alertIds"),
                rows);
    }

    private ExportService.Table flowExport() {
        List<FlowRecord> flows = facade.getFlowRecorder().query(FlowQuery.all(exportMaxRows));
        List<List<String>> rows = new ArrayList<>();
        for (FlowRecord flow : flows) {
            rows.add(List.of(
                    cell(flow.id()),
                    cell(flow.srcIp()),
                    String.valueOf(flow.srcPort()),
                    cell(flow.dstIp()),
                    String.valueOf(flow.dstPort()),
                    cell(flow.protocol()),
                    String.valueOf(flow.bytesOut()),
                    String.valueOf(flow.bytesIn()),
                    String.valueOf(flow.packets()),
                    cell(flow.startTime()),
                    cell(flow.endTime()),
                    String.valueOf(flow.durationMs()),
                    cell(flow.flags()),
                    cell(flow.label()),
                    String.valueOf(flow.simulated())));
        }
        return new ExportService.Table("flows",
                List.of("id", "srcIp", "srcPort", "dstIp", "dstPort", "protocol", "bytesOut", "bytesIn",
                        "packets", "startTime", "endTime", "durationMs", "flags", "label", "simulated"),
                rows);
    }

    private <T> List<T> cap(List<T> rows) {
        if (rows == null || rows.isEmpty()) {
            return List.of();
        }
        return rows.size() <= exportMaxRows ? rows : rows.subList(0, exportMaxRows);
    }

    private static String cell(Object value) {
        return value == null ? "" : value.toString();
    }

    private void setRetention(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "retention.update", "store", AuditLog.Outcome.DENIED,
                    "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        if (rejectsContentType(ctx)) {
            return;
        }
        JsonNode body = readJson(ctx);
        if (body == null || !body.has("minutes")) {
            ctx.status(400).result("");
            return;
        }
        String password = text(body, "password");
        int reauth = reauthStatus(ctx, password);
        if (reauth != 0) {
            audit(ctx, "retention.update", "store", AuditLog.Outcome.DENIED, reauthDetail(reauth));
            ctx.status(reauth).result("");
            return;
        }
        int minutes = body.path("minutes").asInt(-1);
        if (minutes < PersistenceService.MIN_RETENTION_MINUTES
                || minutes > PersistenceService.MAX_RETENTION_MINUTES) {
            audit(ctx, "retention.update", "store", AuditLog.Outcome.DENIED,
                    "rejected " + minutes + " minutes");
            ctx.status(400).result("");
            return;
        }
        PersistenceService store = facade.getPersistenceService();
        int previous = store.setRetentionMinutes(minutes);
        int swept = body.path("sweepNow").asBoolean(false) ? store.sweepNow() : 0;
        audit(ctx, "retention.update", "store", AuditLog.Outcome.ALLOWED,
                "was " + previous + " minutes, now " + minutes + ", swept " + swept + " rows");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("retentionMinutes", store.settings().retentionMinutes());
        result.put("previousMinutes", previous);
        result.put("sweptRows", swept);
        result.put("storeEnabled", store.isEnabled());
        ctx.json(result);
    }

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

    private void flowHistory(Context ctx) {
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
        PersistenceService store = facade.getPersistenceService();
        if (store == null || !store.isEnabled()) {
            ctx.status(503).result("store unavailable");
            return;
        }
        try {
            List<Dtos.FlowDto> rows = new ArrayList<>();
            for (FlowRecord record : store.storedFlows(Math.min(limit, flowApiMax))) {
                rows.add(flowDto(record));
            }
            ctx.json(rows);
        } catch (PersistenceException ex) {
            ctx.status(500).result("store unavailable");
        }
    }

    private void persistenceStatus(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "store.status", "persistence", AuditLog.Outcome.DENIED, "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        PersistenceStatus status = facade.getPersistenceService().status();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", status.enabled());
        body.put("databasePath", status.databasePath());
        body.put("schemaVersion", facade.getPersistenceService().schemaVersion());
        body.put("flowRows", status.flowRows());
        body.put("alertRows", status.alertRows());
        body.put("queuedFlows", status.queuedFlows());
        body.put("queuedAlerts", status.queuedAlerts());
        body.put("droppedRows", status.droppedRows());
        body.put("writtenRows", status.writtenRows());
        body.put("lastFlushAt", status.lastFlushAt());
        body.put("lastError", status.lastError());
        ctx.json(body);
    }

    private void alertQuality(Context ctx) {
        AlertQualityGate gate = facade.getAlertQualityGate();
        AlertQualityGate.Stats stats = gate.stats();
        long raw = facade.getDetectionEngine().getDetectedAlerts();
        long delivered = stats.delivered();
        long suppressed = stats.belowFloor() + stats.ruleSuppressed() + stats.stormSuppressed();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("raw", raw);
        body.put("delivered", delivered);
        body.put("ratio", raw == 0 ? 1.0 : Math.round((delivered * 1000.0) / raw) / 1000.0);
        body.put("folded", stats.duplicates());
        body.put("suppressed", suppressed);
        body.put("belowFloor", stats.belowFloor());
        body.put("ruleSuppressed", stats.ruleSuppressed());
        body.put("stormSuppressed", stats.stormSuppressed());
        body.put("duplicates", stats.duplicates());
        body.put("dedupeEnabled", stats.dedupeEnabled());
        body.put("windowSeconds", gate.getWindowSeconds());
        body.put("minimumSeverity", stats.minimumSeverity());
        body.put("maxPerMinute", stats.maxPerMinute());
        body.put("rules", stats.rules());
        body.put("tracked", stats.tracked());
        ctx.json(body);
    }

    private void intelStatus(Context ctx) {
        ctx.json(intelBody(facade.getIntelService().status()));
    }

    private void reloadIntel(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "intel.reload", "intel", AuditLog.Outcome.DENIED, "role " + ctx.sessionAttribute("role"));
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
        int reauth = reauthStatus(ctx, text(body, "password"));
        if (reauth != 0) {
            audit(ctx, "intel.reload", "intel", AuditLog.Outcome.DENIED, reauthDetail(reauth));
            ctx.status(reauth).result("");
            return;
        }
        IntelService intel = facade.getIntelService();
        try {
            IntelService.Status status = intel.reload();
            audit(ctx, "intel.reload", "intel", AuditLog.Outcome.ALLOWED,
                    status.entries() + " entries from " + status.source());
            ctx.json(intelBody(status));
        } catch (IOException ex) {
            audit(ctx, "intel.reload", "intel", AuditLog.Outcome.DENIED, "unreadable feed " + intel.feedPath());
            Map<String, Object> answer = new LinkedHashMap<>();
            answer.put("error", "feed could not be read");
            answer.put("feed", intel.feedPath());
            ctx.status(422).json(answer);
        }
    }

    private static Map<String, Object> intelBody(IntelService.Status status) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", status.enabled());
        body.put("feed", status.feed());
        body.put("wired", status.wired());
        body.put("entries", status.entries());
        body.put("addresses", status.addresses());
        body.put("domains", status.domains());
        body.put("digests", status.digests());
        body.put("skipped", status.skipped());
        body.put("expired", status.expired());
        body.put("source", status.source());
        body.put("lastReloadAt", status.lastReloadAt() == null ? null : status.lastReloadAt().toString());
        return body;
    }

    private void scenario(Context ctx) {
        if (!Boolean.TRUE.equals(ctx.sessionAttribute("canLaunchAttack"))) {
            audit(ctx, "scenario.run", "simulation", AuditLog.Outcome.DENIED, "role " + ctx.sessionAttribute("role"));
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
        String preset = text(body, "preset");
        String source = text(body, "source");
        String target = text(body, "target");
        long seed = body.path("seed").asLong(config.getInt("app.seed", 42));
        ScenarioService.Result result;
        lock.lock();
        try {
            result = facade.runScenario(preset, source, target, seed);
        } catch (IllegalArgumentException ex) {
            audit(ctx, "scenario.run", "simulation", AuditLog.Outcome.DENIED, "unknown preset " + preset);
            Map<String, Object> answer = new LinkedHashMap<>();
            answer.put("error", "unknown preset");
            answer.put("preset", String.valueOf(preset));
            ctx.status(400).json(answer);
            return;
        } finally {
            lock.unlock();
        }
        audit(ctx, "scenario.run", "simulation", AuditLog.Outcome.ALLOWED,
                result.preset() + " from " + result.source() + " to " + result.target());
        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("preset", result.preset());
        answer.put("title", result.title());
        answer.put("source", result.source());
        answer.put("target", result.target());
        answer.put("events", result.events());
        answer.put("attackTypes", result.attackTypes().stream().map(Enum::name).toList());
        ctx.json(answer);
    }

    private void metrics(Context ctx) {
        DetectionEngine engine = facade.getDetectionEngine();
        AlertQualityGate.Stats gate = facade.getAlertQualityGate().stats();
        PersistenceStatus store = facade.getPersistenceService().status();
        MlFlowScorer.Status model = facade.getMlFlowScorer().status();
        ImportService.Status replay = facade.getImportService().status();
        Runtime runtime = Runtime.getRuntime();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("uptimeSeconds", Math.max(0L, Duration.between(startedAt, Instant.now()).getSeconds()));
        body.put("processedEvents", engine.getProcessedEvents());
        body.put("droppedEvents", engine.getDroppedEvents());
        body.put("queueDepth", engine.getQueue().size());
        body.put("detectedAlerts", engine.getDetectedAlerts());
        body.put("deliveredAlerts", gate.delivered());
        body.put("activeAlerts", facade.getAlertRegistry().size());
        body.put("streamClients", broadcaster.getClientCount());
        body.put("streamFrames", broadcaster.getEmittedFrames());
        body.put("flowsActive", facade.getFlowRecorder().activeCount());
        body.put("flowsClosed", facade.getFlowRecorder().closedCount());
        body.put("storeEnabled", store.enabled());
        body.put("flowRows", store.flowRows());
        body.put("alertRows", store.alertRows());
        body.put("queuedRows", store.queuedFlows() + store.queuedAlerts());
        body.put("writtenRows", store.writtenRows());
        body.put("droppedRows", store.droppedRows());
        body.put("modelState", model.modelState());
        body.put("modelSamples", model.samples());
        body.put("modelScored", model.scored());
        body.put("anomalies", model.anomalies());
        body.put("excludedFromTraining", model.excluded());
        body.put("importState", replay.state().name());
        body.put("importReplayed", replay.replayed());
        body.put("heapUsedBytes", runtime.totalMemory() - runtime.freeMemory());
        body.put("heapMaxBytes", runtime.maxMemory());
        body.put("liveThreads", Thread.activeCount());
        ctx.json(body);
    }

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
        body.put("excluded", status.excluded());
        body.put("lastError", status.lastError());
        ctx.json(body);
    }

    private void mlEvaluation(Context ctx) {
        EvaluationService service = facade.getEvaluationService();
        EvaluationService.Dataset dataset = service.dataset();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("samples", dataset.samples());
        body.put("attackSamples", dataset.attackSamples());
        body.put("benignSamples", dataset.benignSamples());
        body.put("runs", dataset.runs());
        body.put("runIds", dataset.runIds());
        body.put("lastAddedAt", dataset.lastAddedAt());
        ctx.json(body);
    }

    private void evaluateModel(Context ctx) {
        if (!canControlSim(ctx)) {
            audit(ctx, "ml.evaluate", "model", AuditLog.Outcome.DENIED,
                    "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        if (rejectsContentType(ctx)) {
            return;
        }
        EvaluationService.Report report;
        lock.lock();
        try {
            report = facade.evaluateModel();
        } finally {
            lock.unlock();
        }
        audit(ctx, "ml.evaluate", "model", AuditLog.Outcome.ALLOWED, report.samples() + " samples, "
                + report.attackSamples() + " attack, " + report.runs().size() + " runs");
        ctx.json(evaluationBody(report));
    }

    private static Map<String, Object> evaluationBody(EvaluationService.Report report) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("available", report.available());
        body.put("reason", report.reason());
        body.put("generatedAt", report.generatedAt());
        body.put("modelState", report.modelState());
        body.put("trainingSamples", report.trainingSamples());
        body.put("samples", report.samples());
        body.put("attackSamples", report.attackSamples());
        body.put("benignSamples", report.benignSamples());
        body.put("threshold", report.threshold());
        body.put("chosen", report.chosen() == null ? null : pointBody(report.chosen()));
        body.put("best", report.best() == null ? null : pointBody(report.best()));
        body.put("rules", report.rules() == null ? null : ruleBody(report.rules()));
        List<Map<String, Object>> sweep = new ArrayList<>();
        for (EvaluationService.Point point : report.sweep()) {
            sweep.add(pointBody(point));
        }
        body.put("sweep", sweep);
        List<Map<String, Object>> runs = new ArrayList<>();
        for (EvaluationService.RunReport run : report.runs()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", run.id());
            row.put("source", run.source());
            row.put("startedAt", run.startedAt());
            row.put("samples", run.samples());
            row.put("attackSamples", run.attackSamples());
            row.put("benignSamples", run.benignSamples());
            row.put("rules", ruleBody(run.rules()));
            row.put("point", run.point() == null ? null : pointBody(run.point()));
            runs.add(row);
        }
        body.put("runs", runs);
        body.put("note", report.note());
        return body;
    }

    private static Map<String, Object> pointBody(EvaluationService.Point point) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("threshold", point.threshold());
        row.put("truePositives", point.truePositives());
        row.put("falsePositives", point.falsePositives());
        row.put("falseNegatives", point.falseNegatives());
        row.put("trueNegatives", point.trueNegatives());
        row.put("precision", point.precision());
        row.put("recall", point.recall());
        row.put("f1", point.f1());
        row.put("falsePositiveRate", point.falsePositiveRate());
        row.put("accuracy", point.accuracy());
        return row;
    }

    private static Map<String, Object> ruleBody(EvaluationService.RuleRow rule) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("alerted", rule.alerted());
        row.put("truePositives", rule.truePositives());
        row.put("falsePositives", rule.falsePositives());
        row.put("falseNegatives", rule.falseNegatives());
        row.put("trueNegatives", rule.trueNegatives());
        row.put("precision", rule.precision());
        row.put("recall", rule.recall());
        row.put("f1", rule.f1());
        row.put("falsePositiveRate", rule.falsePositiveRate());
        row.put("accuracy", rule.accuracy());
        return row;
    }

    private void correlationStatus(Context ctx) {
        SiemCorrelator.Status status = facade.getSiemCorrelator().status();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", status.enabled());
        body.put("trackedSources", status.trackedSources());
        body.put("signals", status.signals());
        body.put("correlated", status.correlated());
        body.put("minSignals", status.minSignals());
        body.put("windowSeconds", status.windowSeconds());
        body.put("chains", status.chains());
        body.put("chainsMatched", status.chainsMatched());
        body.put("lastChain", status.lastChain());
        body.put("chainProblem", status.chainProblem());
        ctx.json(body);
    }

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
        body.put("mode", status.mode().name());
        body.put("minSeverity", status.minSeverity().name());
        body.put("blocked", rows);
        body.put("droppedEvents", status.droppedEvents());
        body.put("automaticActions", status.automaticActions());
        body.put("expiredActions", status.expiredActions());
        body.put("refusedActions", status.refusedActions());
        ContainmentSafeguards safeguards = facade.getContainmentSafeguards();
        ContainmentSafeguards.Counters counters = safeguards.counters();
        Map<String, Object> guard = new LinkedHashMap<>();
        guard.put("allowlist", safeguards.allowlist());
        guard.put("maxPerMinute", safeguards.maxPerMinute());
        guard.put("partitionCheck", safeguards.partitionCheck());
        guard.put("refusedAllowlist", counters.allowlist());
        guard.put("refusedRateLimit", counters.rateLimit());
        guard.put("refusedPartition", counters.partition());
        body.put("safeguards", guard);
        ctx.json(body);
    }

    private void containmentMode(Context ctx) {
        if (!Boolean.TRUE.equals(ctx.sessionAttribute("canLaunchAttack"))) {
            audit(ctx, "containment.mode", "containment", AuditLog.Outcome.DENIED,
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
        ContainmentService.Mode mode = ContainmentService.parseMode(text(body, "mode"));
        if (mode == null) {
            ctx.status(400).result("");
            return;
        }
        String password = text(body, "password");
        int reauth = reauthStatus(ctx, password);
        if (reauth != 0) {
            audit(ctx, "containment.mode", mode.name(), AuditLog.Outcome.DENIED, reauthDetail(reauth));
            ctx.status(reauth).result("");
            return;
        }
        ContainmentService service = facade.getContainmentService();
        ContainmentService.Mode previous = service.mode();
        service.setMode(mode);
        audit(ctx, "containment.mode", mode.name(), AuditLog.Outcome.ALLOWED,
                "was " + previous + ", enforcing " + service.enforcing());
        broadcaster.requestNetwork();
        broadcaster.broadcastState();
        ctx.json(Map.of("mode", mode.name(), "enabled", service.enabled(),
                "enforce", service.enforcing()));
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
            broadcaster.requestNetwork();
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
        if (removed) {
            broadcaster.requestNetwork();
        }
        ctx.status(removed ? 200 : 404).result("");
    }

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
            row.put("escalation", notification.escalation());
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
        NotificationService.Health health = service.health();
        Map<String, Object> healthBody = new LinkedHashMap<>();
        healthBody.put("console", health.console());
        healthBody.put("email", health.email());
        healthBody.put("emailRecipient", health.emailRecipient());
        healthBody.put("webhookHost", health.webhookHost());
        healthBody.put("webhookRefusal", health.webhookRefusal());
        healthBody.put("breakerOpen", health.breakerOpen());
        healthBody.put("consecutiveFailures", health.consecutiveFailures());
        healthBody.put("breakerUntil", health.breakerUntil());
        healthBody.put("suppressed", health.suppressed());
        healthBody.put("rateLimited", health.rateLimited());
        healthBody.put("cooldownSkipped", health.cooldownSkipped());
        healthBody.put("refused", health.refused());
        healthBody.put("consoleSent", health.consoleSent());
        healthBody.put("emailSent", health.emailSent());
        healthBody.put("emailFailed", health.emailFailed());
        body.put("health", healthBody);
        NotificationService.Settings settings = service.settings();
        Map<String, Object> settingsBody = new LinkedHashMap<>();
        settingsBody.put("retries", settings.retries());
        settingsBody.put("backoffMillis", settings.backoffMillis());
        settingsBody.put("breakerThreshold", settings.breakerThreshold());
        settingsBody.put("breakerCooldownSeconds", settings.breakerCooldownSeconds());
        settingsBody.put("maxPerHour", settings.maxPerHour());
        settingsBody.put("cooldownSeconds", settings.cooldownSeconds());
        settingsBody.put("maxBodyBytes", settings.maxBodyBytes());
        settingsBody.put("allowInsecure", settings.allowInsecure());
        settingsBody.put("redact", settings.redact());
        body.put("settings", settingsBody);
        List<Map<String, Object>> deliveries = new ArrayList<>();
        for (NotificationService.Delivery delivery : service.history(20)) {
            deliveries.add(deliveryRow(delivery));
        }
        body.put("deliveries", deliveries);
        ctx.json(body);
    }

    private void notificationTest(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "notification.test", "notifications", AuditLog.Outcome.DENIED,
                    "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (NotificationService.Delivery delivery : facade.getNotificationService().test()) {
            rows.add(deliveryRow(delivery));
        }
        audit(ctx, "notification.test", "notifications", AuditLog.Outcome.ALLOWED,
                rows.size() + " channels probed");
        ctx.json(Map.of("deliveries", rows));
    }

    private void notificationControl(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "notification.control", "notifications", AuditLog.Outcome.DENIED,
                    "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        if (rejectsContentType(ctx)) {
            return;
        }
        JsonNode body = readJson(ctx);
        if (body == null || !body.has("enabled")) {
            ctx.status(400).result("");
            return;
        }
        String password = text(body, "password");
        int reauth = reauthStatus(ctx, password);
        if (reauth != 0) {
            audit(ctx, "notification.control", "notifications", AuditLog.Outcome.DENIED,
                    reauthDetail(reauth));
            ctx.status(reauth).result("");
            return;
        }
        boolean enabled = body.path("enabled").asBoolean(false);
        NotificationService service = facade.getNotificationService();
        boolean previous = service.isEnabled();
        service.setEnabled(enabled);
        audit(ctx, "notification.control", enabled ? "on" : "off", AuditLog.Outcome.ALLOWED,
                "was " + previous);
        ctx.json(Map.of("enabled", enabled));
    }

    private Map<String, Object> deliveryRow(NotificationService.Delivery delivery) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("at", delivery.at().toString());
        row.put("channel", delivery.channel());
        row.put("outcome", delivery.outcome());
        row.put("attempts", delivery.attempts());
        row.put("detail", delivery.detail());
        return row;
    }

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
        List<Map<String, Object>> controls = new ArrayList<>();
        for (ComplianceService.Control control : service.controls()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", control.id());
            row.put("title", control.title());
            row.put("status", control.status());
            row.put("evidence", control.evidence());
            row.put("indicative", control.indicative());
            controls.add(row);
        }
        body.put("controls", controls);
        body.put("mappingNote", ComplianceService.MAPPING_NOTE);
        ctx.json(body);
    }

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
            List<Map<String, Object>> contained = new ArrayList<>();
            for (ContainmentService.Action action : facade.getContainmentService().active()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("ip", action.ip());
                row.put("expiresAt", action.expiresAt().toString());
                row.put("automatic", action.automatic());
                contained.add(row);
            }
            body.put("contained", contained);
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
                alert.isSimulated(),
                alert.getOccurrences(),
                alert.getFirstSeen() == null ? null : alert.getFirstSeen().toString(),
                alert.getLastSeen() == null ? null : alert.getLastSeen().toString(),
                alert.getStatus().name());
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

    private void importZeek(Context ctx) {
        if (!canControlSim(ctx)) {
            audit(ctx, "import.zeek", "pipeline", AuditLog.Outcome.DENIED,
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
        String connLog = text(body, "connLog");
        if (connLog.isBlank()) {
            ctx.status(400).result("");
            return;
        }
        int maxChars = Math.max(1024, config.getInt("import.request.maxBytes", 8_388_608));
        if (connLog.length() > maxChars) {
            audit(ctx, "import.zeek", "upload", AuditLog.Outcome.DENIED,
                    connLog.length() + " bytes over the limit");
            ctx.status(413).result("");
            return;
        }
        Double speed = pace(body);
        if (speed == null) {
            ctx.status(400).result("");
            return;
        }
        String source = trimToNull(text(body, "source"));
        String labelsName = trimToNull(text(body, "labelsName"));
        lock.lock();
        try {
            ImportService.Status status = facade.getImportService().start(connLog, source,
                    text(body, "labels"), labelsName, speed);
            audit(ctx, "import.zeek", status.source(), AuditLog.Outcome.ALLOWED,
                    connLog.length() + " bytes, " + (speed > 0 ? speed + "x" : "instant"));
            broadcaster.requestNetwork();
            ctx.status(202).json(importBody(status));
        } catch (IllegalStateException ex) {
            ctx.status(409).json(Map.of("error", "an import is already running"));
        } finally {
            lock.unlock();
        }
    }

    private void importStatus(Context ctx) {
        ImportService service = facade.getImportService();
        Map<String, Object> body = importBody(service.status());
        ImportService.Report last = service.lastReport();
        body.put("lastReport", last == null ? null : importReportBody(last));
        ctx.json(body);
    }

    private void importSample(Context ctx) {
        String connLog = resource("/samples/sample-conn.log");
        if (connLog == null) {
            ctx.status(404).result("");
            return;
        }
        String labels = resource("/samples/sample-conn.labels.csv");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("connLog", connLog);
        body.put("labels", labels == null ? "" : labels);
        body.put("source", "sample-conn.log");
        body.put("labelsName", "sample-conn.labels.csv");
        ctx.json(body);
    }

    private static Double pace(JsonNode body) {
        JsonNode node = body.get("speed");
        if (node == null || node.isNull()) {
            return 0.0;
        }
        double value;
        if (node.isNumber()) {
            value = node.asDouble();
        } else if (node.isTextual()) {
            try {
                value = Double.parseDouble(node.asText().trim());
            } catch (NumberFormatException ex) {
                return null;
            }
        } else {
            return null;
        }
        if (Double.isNaN(value) || value < 0 || value > 10_000) {
            return null;
        }
        return value;
    }

    private Map<String, Object> importBody(ImportService.Status status) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("state", status.state().name());
        body.put("source", status.source());
        body.put("flows", status.flows());
        body.put("replayed", status.replayed());
        body.put("progress", status.progress());
        body.put("alerts", status.alerts());
        body.put("paced", status.paced());
        body.put("speed", status.speed());
        body.put("elapsedMillis", status.elapsedMillis());
        body.put("error", status.error());
        return body;
    }

    private Map<String, Object> importReportBody(ImportService.Report report) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("source", report.source());
        body.put("labelsSource", report.labelsSource());
        body.put("flows", report.flows());
        body.put("skipped", report.skipped());
        body.put("events", report.events());
        body.put("unknownHosts", report.unknownHosts());
        body.put("stored", report.stored());
        body.put("detected", report.detected());
        body.put("alerts", report.alerts());
        body.put("folded", report.folded());
        body.put("paced", report.paced());
        body.put("speed", report.speed());
        body.put("elapsedMillis", report.elapsedMillis());
        body.put("completed", report.completed());
        body.put("firstTimestamp", report.firstTimestamp() == null ? null : report.firstTimestamp().toString());
        body.put("lastTimestamp", report.lastTimestamp() == null ? null : report.lastTimestamp().toString());
        body.put("unknownHostIps", report.unknownHostIps());
        body.put("problems", report.problems());
        List<Map<String, Object>> labels = new ArrayList<>();
        for (ImportService.LabelStat stat : report.labels()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("label", stat.label());
            row.put("flows", stat.flows());
            row.put("alerts", stat.alerts());
            labels.add(row);
        }
        body.put("labels", labels);
        return body;
    }

    private String resource(String path) {
        try (InputStream in = ApiRoutes.class.getResourceAsStream(path)) {
            return in == null ? null : new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            return null;
        }
    }

    private void configuration(Context ctx) {
        if (!"Admin".equals(ctx.sessionAttribute("role"))) {
            audit(ctx, "config.read", "configuration", AuditLog.Outcome.DENIED,
                    "role " + ctx.sessionAttribute("role"));
            ctx.status(403).result("");
            return;
        }
        audit(ctx, "config.read", "configuration", AuditLog.Outcome.ALLOWED, "thresholds and session policy");
        Map<String, Object> thresholds = new LinkedHashMap<>();
        for (String key : List.of(
                "risk.cap", "risk.compromiseThreshold", "incident.correlationWindowSeconds",
                "detection.cooldownSeconds", "detection.rate.windowSeconds", "detection.rate.maxFailures",
                "detection.portScan.windowSeconds", "detection.portScan.maxDistinctPorts",
                "detection.portScan.maxDistinctHosts", "detection.anomaly.zThreshold",
                "detection.anomaly.warmupCount", "alerts.buffer.max", "stream.network.intervalMillis",
                "ml.anomalyThreshold", "ml.minSamples", "ml.train.exclusionSeconds")) {
            thresholds.put(key, config.getString(key, ""));
        }
        Map<String, Object> simulation = new LinkedHashMap<>();
        SimulationNoise noise = facade.getTrafficSimulator().getNoise();
        simulation.put("noiseEnabled", noise.enabled());
        simulation.put("attackVariantChance", noise.attackVariantChance());
        simulation.put("benignSpikeChance", config.getDouble("sim.noise.benignSpikeChance", 0.03));
        simulation.put("retryChance", config.getDouble("sim.noise.retryChance", 0.05));
        simulation.put("portSpreadChance", config.getDouble("sim.noise.portSpreadChance", 0.10));
        Map<String, Object> session = new LinkedHashMap<>();
        session.put("timeoutSeconds", sessionMaxAgeSeconds);
        session.put("absoluteTimeoutSeconds", absoluteSessionSeconds);
        session.put("csrfEnabled", csrfEnabled);
        session.put("reauthEnabled", reauthEnabled);
        session.put("reauthFreshSeconds", reauthFreshSeconds);
        session.put("loginMaxAttempts", loginThrottle.getMaxAttempts());
        session.put("loginWindowSeconds", loginThrottle.getWindowSeconds());
        List<Map<String, String>> accounts = new ArrayList<>();
        accounts.add(account("auth.defaultUsername", "Admin"));
        accounts.add(account("auth.analystUsername", "Analyst"));
        accounts.add(account("auth.viewerUsername", "Viewer"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("thresholds", thresholds);
        body.put("simulation", simulation);
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
