package pk.ooad.ntd.service;

import pk.ooad.ntd.compliance.ComplianceService;
import pk.ooad.ntd.containment.ContainmentSafeguards;
import pk.ooad.ntd.containment.ContainmentService;
import pk.ooad.ntd.correlation.SiemCorrelator;
import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.detection.AlertQualityGate;
import pk.ooad.ntd.detection.AlertRegistry;
import pk.ooad.ntd.detection.AlertUpdateListener;
import pk.ooad.ntd.detection.DetectionEngine;
import pk.ooad.ntd.detection.Detector;
import pk.ooad.ntd.detection.DetectorFactory;
import pk.ooad.ntd.detection.ThreatIntelDetector;
import pk.ooad.ntd.detection.SuppressionRules;
import pk.ooad.ntd.flows.FlowQuery;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.flows.FlowRecorder;
import pk.ooad.ntd.forensics.EvidenceExporter;
import pk.ooad.ntd.imports.ImportService;
import pk.ooad.ntd.ml.EvaluationService;
import pk.ooad.ntd.ml.MlFlowScorer;
import pk.ooad.ntd.notify.NotificationService;
import pk.ooad.ntd.persistence.AlertRecord;
import pk.ooad.ntd.persistence.AuditRecord;
import pk.ooad.ntd.persistence.ContainmentRecord;
import pk.ooad.ntd.persistence.IncidentRecord;
import pk.ooad.ntd.persistence.ManifestRecord;
import pk.ooad.ntd.persistence.ModelSummaryRecord;
import pk.ooad.ntd.persistence.PersistenceService;
import pk.ooad.ntd.security.AuditLog;
import pk.ooad.ntd.security.SecurityPolicy;
import pk.ooad.ntd.domain.Admin;
import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertStatus;
import pk.ooad.ntd.domain.IncidentStatus;
import pk.ooad.ntd.domain.SecurityAnalyst;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.domain.Viewer;
import pk.ooad.ntd.domain.AssetStatus;
import pk.ooad.ntd.domain.AssetType;
import pk.ooad.ntd.domain.AssignmentResult;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.BackboneResult;
import pk.ooad.ntd.domain.MitigationTask;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.ResponsePlan;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.domain.User;
import pk.ooad.ntd.response.AssignmentPlanner;
import pk.ooad.ntd.response.BackbonePlanner;
import pk.ooad.ntd.simulation.ScenarioService;
import pk.ooad.ntd.simulation.TrafficSimulator;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class IncidentResponseFacade {
    private final Network network;
    private final TrafficSimulator trafficSimulator;
    private final DetectionEngine detectionEngine;
    private final AlertBus alertBus;
    private final FlowRecorder flowRecorder;
    private final MlFlowScorer mlFlowScorer;
    private final PersistenceService persistenceService;
    private final AuditLog auditLog;
    private final SecurityPolicy securityPolicy;
    private final AlertQualityGate alertQualityGate;
    private final AlertRegistry alertRegistry;
    private final SiemCorrelator siemCorrelator;
    private final ContainmentService containmentService;
    private final ContainmentSafeguards containmentSafeguards;
    private final NotificationService notificationService;
    private final EvidenceExporter evidenceExporter;
    private final ComplianceService complianceService;
    private final IntelService intelService;
    private final ThreatIntelDetector intelDetector;
    private final ScenarioService scenarioService;
    private final ImportService importService;
    private final EvaluationService evaluationService;
    private final RiskScorer riskScorer;
    private final IncidentManager incidentManager;
    private final SOC soc;
    private final AuthService authService;
    private final BackbonePlanner backbonePlanner;
    private final AssignmentPlanner assignmentPlanner;
    private final ReportGenerator reportGenerator;
    private final List<MitigationTask> responseTasks;
    private final List<AnalystTeam> responseTeams;
    private final List<Alert> restoredAlerts = new ArrayList<>();
    private User currentUser;
    private ResponsePlan lastResponsePlan;
    private RestoreReport restoreReport;

    public record RestoreReport(boolean durable, int schemaVersion, int alerts, int incidents,
                                int containment, int audit, boolean model) {

        public String summary() {
            if (!durable) {
                return "No durable store open; nothing was restored";
            }
            return "Restored schema " + schemaVersion + ": " + alerts + " alerts, " + incidents
                    + " incidents, " + containment + " blocks, " + audit + " audit entries"
                    + (model ? ", model summary" : "");
        }
    }

    public IncidentResponseFacade() {
        this(TopologyLoader.loadSample(), 0L);
    }

    public IncidentResponseFacade(Network network, long seed) {
        this(network, Clock.systemUTC(), seed, List.of(), null);
    }

    public IncidentResponseFacade(Network network, Clock clock, long seed) {
        this(network, clock, seed, List.of(), null);
    }

    IncidentResponseFacade(Network network, long seed, List<MitigationTask> tasks, List<AnalystTeam> teams) {
        this(network, Clock.systemUTC(), seed, tasks, teams);
    }

    IncidentResponseFacade(Network network, Clock clock, long seed, List<MitigationTask> tasks, List<AnalystTeam> teams) {
        this.network = Objects.requireNonNull(network, "network must not be null");
        responseTasks = tasks == null ? List.of() : List.copyOf(tasks);
        responseTeams = teams == null ? null : List.copyOf(teams);
        trafficSimulator = new TrafficSimulator(network, clock, seed);
        scenarioService = new ScenarioService();
        alertBus = new AlertBus();
        detectionEngine = new DetectionEngine(trafficSimulator.getEventQueue(), alertBus,
                ConfigManager.getInstance().getInt("detection.cooldownSeconds", 5));
        ThreatIntelDetector threatIntel = null;
        for (Detector detector : new DetectorFactory().createAll()) detectionEngine.addDetector(detector);
        for (Detector detector : new DetectorFactory().createNdr()) {
            detectionEngine.addDetector(detector);
            if (detector instanceof ThreatIntelDetector intel) {
                threatIntel = intel;
            }
        }
        intelDetector = threatIntel;
        alertQualityGate = new AlertQualityGate(ConfigManager.getInstance(), new SuppressionRules());
        detectionEngine.setAlertGate(alertQualityGate);
        alertRegistry = new AlertRegistry();
        flowRecorder = new FlowRecorder();
        detectionEngine.addEventObserver(flowRecorder);
        mlFlowScorer = new MlFlowScorer(alertBus, alertQualityGate);
        flowRecorder.addCloseListener(mlFlowScorer::onFlow);
        persistenceService = new PersistenceService();
        flowRecorder.addCloseListener(persistenceService::recordFlow);
        importService = new ImportService(network, detectionEngine, flowRecorder, persistenceService);
        importService.setFlowSink(new ImportService.FlowSink() {
            @Override
            public void record(FlowRecord flow) {
                mlFlowScorer.onFlow(flow);
            }

            @Override
            public void history(FlowRecord flow) {
                persistenceService.recordFlow(flow);
            }
        });
        ConfigManager config = ConfigManager.getInstance();
        evaluationService = new EvaluationService(config);
        importService.setSampleSink(evaluationService::add);
        auditLog = new AuditLog();
        siemCorrelator = new SiemCorrelator(alertBus);
        containmentService = new ContainmentService();
        containmentSafeguards = new ContainmentSafeguards(clock, ConfigManager.getInstance(), () -> network);
        containmentService.setSafeguard(containmentSafeguards::refusal);
        detectionEngine.setAdmission(containmentService::admit);
        notificationService = new NotificationService();
        riskScorer = new RiskScorer(network);
        incidentManager = new IncidentManager();
        soc = new SOC(detectionEngine);
        soc.addTeam(new AnalystTeam("default-team", "Default SOC Team", Set.of(),
                ConfigManager.getInstance().getInt("soc.defaultTeamCapacity", 100), true));
        securityPolicy = SecurityPolicy.from(config);
        authService = new AuthService(List.of(
                new Admin(config.getString("auth.defaultUsername", "admin"),
                        SecurityPolicy.credentialFor(config, "auth.defaultPassword", "NTD_ADMIN_PASSWORD")),
                new SecurityAnalyst(config.getString("auth.analystUsername", "analyst"),
                        SecurityPolicy.credentialFor(config, "auth.analystPassword", "NTD_ANALYST_PASSWORD")),
                new Viewer(config.getString("auth.viewerUsername", "viewer"),
                        SecurityPolicy.credentialFor(config, "auth.viewerPassword", "NTD_VIEWER_PASSWORD"))));
        backbonePlanner = new BackbonePlanner();
        assignmentPlanner = new AssignmentPlanner();
        reportGenerator = new ReportGenerator();
        evidenceExporter = new EvidenceExporter(ConfigManager.getInstance());
        complianceService = new ComplianceService(persistenceService, auditLog,
                notificationService, containmentService, evidenceExporter, ConfigManager.getInstance());
        intelService = new IntelService(intelDetector);
        alertBus.subscribe(riskScorer);
        alertBus.subscribe(new AlertLogger());
        alertBus.subscribe(incidentManager);
        alertBus.subscribe(persistenceService);
        alertBus.subscribe(siemCorrelator);
        alertBus.subscribe(containmentService);
        alertBus.subscribe(notificationService);
        alertBus.subscribe(alertRegistry);
        alertBus.subscribeUpdate(persistenceService);
        alertBus.subscribeUpdate(alertRegistry);
        wirePersistence();
    }

    private void wirePersistence() {
        auditLog.setRecorder(entry -> persistenceService.recordAudit(new AuditRecord(entry.timestamp(),
                entry.actor(), entry.action(), entry.target(), entry.outcome(), entry.detail())));
        containmentService.setRecorder(new ContainmentService.Recorder() {
            @Override
            public void blocked(ContainmentService.Action action, boolean automatic) {
                persistenceService.recordContainment(new ContainmentRecord(action.ip(), action.blockedAt(),
                        action.expiresAt(), action.reason(), action.actor(), automatic, false));
            }

            @Override
            public void released(ContainmentService.Action action) {
                persistenceService.recordContainment(new ContainmentRecord(action.ip(), action.blockedAt(),
                        action.expiresAt(), action.reason(), action.actor(), action.automatic(), true));
            }
        });
        incidentManager.setRecorder(this::recordIncident);
        mlFlowScorer.setTrainingListener(this::recordModelSummary);
        notificationService.setRecorder((channel, outcome, detail) -> auditLog.record("system",
                "notification." + channel, channel,
                "sent".equals(outcome) ? AuditLog.Outcome.ALLOWED
                        : "failed".equals(outcome) ? AuditLog.Outcome.FAILED
                        : AuditLog.Outcome.DENIED,
                detail));
        importService.setCompletionListener(report -> auditLog.record("system", "import.replay",
                report.source(), AuditLog.Outcome.ALLOWED, report.summary()));
    }

    private void recordIncident(Incident incident) {
        Severity highest = incident.getHighestSeverity();
        persistenceService.recordIncident(new IncidentRecord(incident.getId(), incident.getOpenedAt(),
                incident.getSourceIp(), incident.getStatus().name(),
                highest == null ? "" : highest.name(), incident.alertIds()));
    }

    private void recordModelSummary(MlFlowScorer.Status status) {
        persistenceService.recordModelSummary(new ModelSummaryRecord(trainedAt(status.lastTrainedAt()),
                status.modelState(), status.samples(), status.clusters(), status.threshold()));
    }

    public RestoreReport restore() {
        if (restoreReport != null) {
            return restoreReport;
        }
        ConfigManager config = ConfigManager.getInstance();
        int alertCap = Math.max(1, config.getInt("alerts.buffer.max", 500));
        int incidentCap = Math.max(1, config.getInt("persistence.restore.incidents", 200));
        int auditCap = Math.max(1, config.getInt("audit.maxRecords", 2000));
        int blockCap = Math.max(1, config.getInt("containment.maxBlocked", 500));

        List<AlertRecord> alertRows = readOrEmpty(() -> persistenceService.storedAlerts(Math.max(alertCap, incidentCap)));
        Map<String, Alert> byId = new HashMap<>();
        List<Alert> seeded = new ArrayList<>();
        for (AlertRecord row : alertRows) {
            Alert alert = row.toAlert();
            if (alert == null) {
                continue;
            }
            byId.put(row.id(), alert);
        }
        for (AlertRecord row : alertRows) {
            Alert alert = byId.get(row.id());
            if (alert != null && seeded.size() < alertCap) {
                seeded.add(alert);
            }
        }
        Collections.reverse(seeded);
        restoredAlerts.clear();
        restoredAlerts.addAll(seeded);

        List<AuditLog.Entry> trail = new ArrayList<>();
        for (AuditRecord row : readOrEmpty(() -> persistenceService.storedAudit(auditCap))) {
            trail.add(new AuditLog.Entry(0L, row.timestamp(), row.actor(), row.action(), row.target(),
                    row.outcome(), row.detail()));
        }
        Collections.reverse(trail);
        auditLog.restore(trail);

        int blocks = 0;
        for (ContainmentRecord row : readOrEmpty(() -> persistenceService.storedContainment(blockCap))) {
            if (row.released()) {
                continue;
            }
            if (containmentService.restore(new ContainmentService.Action(row.ip(), row.blockedAt(),
                    row.expiresAt(), row.reason(), row.actor(), row.automatic()))) {
                blocks++;
            }
        }

        List<Incident> rebuilt = new ArrayList<>();
        for (IncidentRecord row : readOrEmpty(() -> persistenceService.storedIncidents(incidentCap))) {
            List<Alert> alerts = new ArrayList<>();
            for (String id : row.alertIds()) {
                Alert alert = byId.get(id);
                if (alert != null) {
                    alerts.add(alert);
                }
            }
            rebuilt.add(new Incident(row.id(), row.sourceIp(), row.openedAt(), status(row.status()), alerts));
        }
        Collections.reverse(rebuilt);
        incidentManager.restore(rebuilt);

        boolean model = readOrEmpty(() -> persistenceService.storedModelSummaries(1)).stream().findFirst().isPresent();
        restoreReport = new RestoreReport(persistenceService.isEnabled(), persistenceService.schemaVersion(),
                seeded.size(), rebuilt.size(), blocks, trail.size(), model);
        return restoreReport;
    }

    public List<Alert> restoredAlerts() {
        return List.copyOf(restoredAlerts);
    }

    private static <T> List<T> readOrEmpty(java.util.function.Supplier<List<T>> read) {
        try {
            return read.get();
        } catch (RuntimeException ex) {
            return List.of();
        }
    }

    private static IncidentStatus status(String raw) {
        if (raw == null || raw.isBlank()) {
            return IncidentStatus.OPEN;
        }
        try {
            return IncidentStatus.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return IncidentStatus.OPEN;
        }
    }

    private static Instant trainedAt(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(raw);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    public User login(String u, String p) {
        try {
            currentUser = authService.login(u, p);
            return currentUser;
        } catch (pk.ooad.ntd.domain.AuthenticationException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    public boolean verifyPassword(String username, String password) {
        return authService.verify(username, password);
    }

    public void start() {
        detectionEngine.start();
        trafficSimulator.start();
    }

    public void stop() {
        trafficSimulator.stop();
        detectionEngine.stop();
    }

    public void shutdown() {
        stop();
        flowRecorder.closeAllOpen();
        mlFlowScorer.close();
        notificationService.shutdown();
        persistenceService.close();
    }

    public void reset() {
        stop();
        importService.reset();
        trafficSimulator.reset();
        detectionEngine.reset();
        alertQualityGate.reset();
        alertRegistry.clear();
        flowRecorder.reset();
        mlFlowScorer.reset();
        evaluationService.clear();
        siemCorrelator.reset();
        containmentService.reset();
        notificationService.reset();
        incidentManager.reset();
        riskScorer.reset();
        lastResponsePlan = null;
    }

    public void setAutoMode(boolean on) {
        trafficSimulator.setAutoMode(on);
    }

    public boolean isRunning() {
        return trafficSimulator.isRunning();
    }

    public boolean isAutoMode() {
        return trafficSimulator.isAutoMode();
    }

    public void launchAttack(AttackType type, String src, String dst) {
        trafficSimulator.injectAttack(type, src, dst);
    }

    public ResponsePlan runResponse() {
        BackboneResult backbone = backbonePlanner.plan(network);
        List<MitigationTask> tasks = new java.util.ArrayList<>(responseTasks);
        tasks.addAll(containmentTasks());
        int daysUnpatched = ConfigManager.getInstance().getInt("task.days.unpatched.default", 0);
        for (var asset : network.getAssets()) {
            if (asset.getStatus() != AssetStatus.COMPROMISED && asset.getStatus() != AssetStatus.SUSPICIOUS) {
                continue;
            }
            if (tasks.stream().anyMatch(task -> task.getTarget().getId().equals(asset.getId()))) {
                continue;
            }
            int value = Math.toIntExact(Math.round(asset.getRiskScore() * asset.getCriticality()));
            int cost = taskCost(asset.getType());
            tasks.add(new MitigationTask("risk-" + asset.getId(), asset, value, cost, "", daysUnpatched));
        }
        List<MitigationTask> reachableTasks = tasks.stream()
                .filter(task -> network.getAsset(task.getTarget().getId()) != null)
                .filter(task -> !backbone.getUnreachable().contains(task.getTarget()))
                .map(this::applyValueDecay)
                .toList();
        List<AnalystTeam> teams = responseTeams != null ? responseTeams : soc.getAvailableTeams();
        AssignmentResult assignment = assignmentPlanner.plan(reachableTasks, teams);
        lastResponsePlan = new ResponsePlan(backbone, assignment);
        return lastResponsePlan;
    }

    public List<AnalystTeam> listTeams() {
        return responseTeams != null ? responseTeams : soc.getAvailableTeams();
    }

    public ResponsePlan runResponse(Set<String> excludedHostIds, Map<String, Integer> capacities) {
        boolean plain = (excludedHostIds == null || excludedHostIds.isEmpty())
                && (capacities == null || capacities.isEmpty());
        if (plain) {
            return runResponse();
        }
        Set<String> excluded = excludedHostIds == null ? Set.of() : excludedHostIds;
        Network view = new Network();
        for (var asset : network.getAssets()) {
            if (!excluded.contains(asset.getId())) {
                view.addAsset(asset);
            }
        }
        for (pk.ooad.ntd.domain.Link link : network.getLinks()) {
            if (view.getAsset(link.getSource().getId()) != null && view.getAsset(link.getTarget().getId()) != null) {
                view.addLink(link);
            }
        }
        BackboneResult backbone = backbonePlanner.plan(view);
        List<MitigationTask> tasks = new ArrayList<>(responseTasks);
        tasks.addAll(containmentTasks());
        int daysUnpatched = ConfigManager.getInstance().getInt("task.days.unpatched.default", 0);
        for (var asset : view.getAssets()) {
            if (asset.getStatus() != AssetStatus.COMPROMISED && asset.getStatus() != AssetStatus.SUSPICIOUS) {
                continue;
            }
            if (tasks.stream().anyMatch(task -> task.getTarget().getId().equals(asset.getId()))) {
                continue;
            }
            int value = Math.toIntExact(Math.round(asset.getRiskScore() * asset.getCriticality()));
            int cost = taskCost(asset.getType());
            tasks.add(new MitigationTask("risk-" + asset.getId(), asset, value, cost, "", daysUnpatched));
        }
        List<MitigationTask> reachableTasks = tasks.stream()
                .filter(task -> view.getAsset(task.getTarget().getId()) != null)
                .filter(task -> !backbone.getUnreachable().contains(task.getTarget()))
                .map(this::applyValueDecay)
                .toList();
        List<AnalystTeam> teams = new ArrayList<>();
        for (AnalystTeam team : listTeams()) {
            Integer capacity = capacities == null ? null : capacities.get(team.getName());
            if (capacity == null) {
                teams.add(team);
            } else {
                teams.add(new AnalystTeam(team.getId(), team.getName(), team.getSkills(), capacity, team.isAvailable()));
            }
        }
        AssignmentResult assignment = assignmentPlanner.plan(reachableTasks, teams);
        lastResponsePlan = new ResponsePlan(backbone, assignment);
        return lastResponsePlan;
    }

    private int taskCost(AssetType type) {
        ConfigManager config = ConfigManager.getInstance();
        return switch (type) {
            case SERVER -> config.getInt("task.cost.server", 8);
            case WORKSTATION -> config.getInt("task.cost.workstation", 6);
            case ROUTER -> config.getInt("task.cost.router", 12);
            case IOT_DEVICE -> config.getInt("task.cost.iot", 4);
        };
    }

    private List<MitigationTask> containmentTasks() {
        List<MitigationTask> tasks = new ArrayList<>();
        if (!containmentService.enabled()) {
            return tasks;
        }
        int daysUnpatched = ConfigManager.getInstance().getInt("task.days.unpatched.default", 0);
        for (ContainmentService.Action action : containmentService.active()) {
            if (!action.automatic()) {
                continue;
            }
            NetworkAsset asset = network.findByIp(action.ip());
            if (asset == null) {
                continue;
            }
            int value = Math.toIntExact(Math.round(asset.getRiskScore() * asset.getCriticality()));
            tasks.add(new MitigationTask("contain-" + asset.getId(), asset, Math.max(value, 1),
                    taskCost(asset.getType()), "", daysUnpatched));
        }
        return tasks;
    }

    private MitigationTask applyValueDecay(MitigationTask task) {
        double decayRate = ConfigManager.getInstance().getDouble("decay.rate", 0.0);
        double adjustedValue = task.getValue() * (1.0 + decayRate * task.getDaysUnpatched());
        int finalValue = Math.toIntExact(Math.round(adjustedValue));
        return new MitigationTask(task.getId(), task.getTarget(), finalValue, task.getCost(),
                task.getRequiredSkill(), task.getDaysUnpatched());
    }

    public String generateReport() {
        return reportGenerator.generate(incidentManager.getIncidents(), network, lastResponsePlan);
    }

    public void exportReport(String path) {
        reportGenerator.export(generateReport(), path);
    }

    public void addAlertListener(AlertListener l) {
        alertBus.subscribe(l);
    }

    public void addAlertUpdateListener(AlertUpdateListener l) {
        alertBus.subscribeUpdate(l);
    }

    public record StatusChange(Alert alert, AlertStatus previous, boolean moved) {
    }

    public StatusChange moveAlertStatus(String id, AlertStatus next) {
        Alert alert = alertRegistry.find(id).orElse(null);
        if (alert == null) {
            return null;
        }
        AlertStatus previous = alert.getStatus();
        boolean moved = alert.moveTo(next);
        if (moved) {
            alertBus.publishUpdate(alert);
        }
        return new StatusChange(alert, previous, moved);
    }

    public AlertRegistry getAlertRegistry() {
        return alertRegistry;
    }

    public SuppressionRules getSuppressionRules() {
        return alertQualityGate.getRules();
    }

    public Network getNetwork() {
        return network;
    }

    public List<Incident> getIncidents() {
        return incidentManager.getIncidents();
    }

    public FlowRecorder getFlowRecorder() {
        return flowRecorder;
    }

    public MlFlowScorer getMlFlowScorer() {
        return mlFlowScorer;
    }

    public PersistenceService getPersistenceService() {
        return persistenceService;
    }

    public AuditLog getAuditLog() {
        return auditLog;
    }

    public SecurityPolicy getSecurityPolicy() {
        return securityPolicy;
    }

    public AlertQualityGate getAlertQualityGate() {
        return alertQualityGate;
    }

    public DetectionEngine getDetectionEngine() {
        return detectionEngine;
    }

    public SiemCorrelator getSiemCorrelator() {
        return siemCorrelator;
    }

    public ContainmentService getContainmentService() {
        return containmentService;
    }

    public ContainmentSafeguards getContainmentSafeguards() {
        return containmentSafeguards;
    }

    public NotificationService getNotificationService() {
        return notificationService;
    }

    public EvidenceExporter getEvidenceExporter() {
        return evidenceExporter;
    }

    public ComplianceService getComplianceService() {
        return complianceService;
    }

    public IntelService getIntelService() {
        return intelService;
    }

    public ScenarioService getScenarioService() {
        return scenarioService;
    }

    public ScenarioService.Result runScenario(String preset, String source, String target, long seed) {
        return scenarioService.run(preset, source, target, seed, detectionEngine::processNow);
    }

    public ImportService getImportService() {
        return importService;
    }

    public TrafficSimulator getTrafficSimulator() {
        return trafficSimulator;
    }

    public EvaluationService getEvaluationService() {
        return evaluationService;
    }

    public EvaluationService.Report evaluateModel() {
        MlFlowScorer.Status status;
        if (mlFlowScorer.isEnabled()) {
            mlFlowScorer.train();
        }
        status = mlFlowScorer.status();
        return evaluationService.evaluate(mlFlowScorer::scoreFeatures,
                "ready".equals(status.modelState()), status.modelState(), status.samples(),
                status.threshold());
    }

    public EvidenceExporter.Bundle exportEvidence(String actor, List<Alert> liveAlerts) {
        int maxFlows = ConfigManager.getInstance().getInt("forensics.maxFlows", 5000);
        int maxAlerts = ConfigManager.getInstance().getInt("forensics.maxAlerts", 5000);
        List<FlowRecord> flows;
        try {
            flows = persistenceService.isEnabled()
                    ? persistenceService.storedFlows(maxFlows)
                    : flowRecorder.query(FlowQuery.all(maxFlows));
        } catch (RuntimeException ex) {
            flows = flowRecorder.query(FlowQuery.all(maxFlows));
        }
        List<AlertRecord> alerts = new ArrayList<>();
        if (liveAlerts != null) {
            for (Alert alert : liveAlerts) {
                alerts.add(AlertRecord.from(alert));
            }
        }
        if (alerts.isEmpty()) {
            try {
                alerts = persistenceService.storedAlerts(maxAlerts);
            } catch (RuntimeException ignored) {
                alerts = List.of();
            }
        }
        int auditCap = ConfigManager.getInstance().getInt("audit.maxRecords", 2000);
        EvidenceExporter.Bundle bundle = evidenceExporter.export(actor, flows, alerts, auditLog.recent(auditCap),
                getIncidents());
        persistenceService.recordManifest(new ManifestRecord(bundle.directory(), trainedAt(bundle.createdAt()),
                bundle.files(), bundle.bytes(), bundle.manifestSha256()));
        return bundle;
    }
}
