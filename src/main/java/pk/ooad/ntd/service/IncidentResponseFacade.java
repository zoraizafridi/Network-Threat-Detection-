package pk.ooad.ntd.service;

import pk.ooad.ntd.compliance.ComplianceService;
import pk.ooad.ntd.containment.ContainmentService;
import pk.ooad.ntd.correlation.SiemCorrelator;
import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.detection.AlertQualityGate;
import pk.ooad.ntd.detection.DetectionEngine;
import pk.ooad.ntd.detection.Detector;
import pk.ooad.ntd.detection.DetectorFactory;
import pk.ooad.ntd.flows.FlowQuery;
import pk.ooad.ntd.flows.FlowRecord;
import pk.ooad.ntd.flows.FlowRecorder;
import pk.ooad.ntd.forensics.EvidenceExporter;
import pk.ooad.ntd.ml.MlFlowScorer;
import pk.ooad.ntd.notify.NotificationService;
import pk.ooad.ntd.persistence.AlertRecord;
import pk.ooad.ntd.persistence.PersistenceService;
import pk.ooad.ntd.security.AuditLog;
import pk.ooad.ntd.domain.Admin;
import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.SecurityAnalyst;
import pk.ooad.ntd.domain.Viewer;
import pk.ooad.ntd.domain.AssetStatus;
import pk.ooad.ntd.domain.AssetType;
import pk.ooad.ntd.domain.AssignmentResult;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.BackboneResult;
import pk.ooad.ntd.domain.MitigationTask;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.ResponsePlan;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.domain.User;
import pk.ooad.ntd.response.AssignmentPlanner;
import pk.ooad.ntd.response.BackbonePlanner;
import pk.ooad.ntd.simulation.TrafficSimulator;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
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
    private final AlertQualityGate alertQualityGate;
    private final SiemCorrelator siemCorrelator;
    private final ContainmentService containmentService;
    private final NotificationService notificationService;
    private final EvidenceExporter evidenceExporter;
    private final ComplianceService complianceService;
    private final RiskScorer riskScorer;
    private final IncidentManager incidentManager;
    private final SOC soc;
    private final AuthService authService;
    private final BackbonePlanner backbonePlanner;
    private final AssignmentPlanner assignmentPlanner;
    private final ReportGenerator reportGenerator;
    private final List<MitigationTask> responseTasks;
    private final List<AnalystTeam> responseTeams;
    private User currentUser;
    private ResponsePlan lastResponsePlan;

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
        alertBus = new AlertBus();
        detectionEngine = new DetectionEngine(trafficSimulator.getEventQueue(), alertBus,
                ConfigManager.getInstance().getInt("detection.cooldownSeconds", 5));
        for (Detector detector : new DetectorFactory().createAll()) detectionEngine.addDetector(detector);
        for (Detector detector : new DetectorFactory().createNdr()) detectionEngine.addDetector(detector);
        alertQualityGate = new AlertQualityGate();
        detectionEngine.setAlertGate(alertQualityGate);
        flowRecorder = new FlowRecorder();
        detectionEngine.addEventObserver(flowRecorder);
        mlFlowScorer = new MlFlowScorer(alertBus, alertQualityGate);
        flowRecorder.addCloseListener(mlFlowScorer::onFlow);
        persistenceService = new PersistenceService();
        flowRecorder.addCloseListener(persistenceService::recordFlow);
        auditLog = new AuditLog();
        siemCorrelator = new SiemCorrelator(alertBus);
        containmentService = new ContainmentService();
        detectionEngine.setAdmission(containmentService::admit);
        notificationService = new NotificationService();
        riskScorer = new RiskScorer(network);
        incidentManager = new IncidentManager();
        soc = new SOC(detectionEngine);
        soc.addTeam(new AnalystTeam("default-team", "Default SOC Team", Set.of(),
                ConfigManager.getInstance().getInt("soc.defaultTeamCapacity", 100), true));
        ConfigManager config = ConfigManager.getInstance();
        authService = new AuthService(List.of(
                new Admin(config.getString("auth.defaultUsername", "admin"),
                        config.getString("auth.defaultPassword", "admin")),
                new SecurityAnalyst(config.getString("auth.analystUsername", "analyst"),
                        config.getString("auth.analystPassword", "analyst")),
                new Viewer(config.getString("auth.viewerUsername", "viewer"),
                        config.getString("auth.viewerPassword", "viewer"))));
        backbonePlanner = new BackbonePlanner();
        assignmentPlanner = new AssignmentPlanner();
        reportGenerator = new ReportGenerator();
        evidenceExporter = new EvidenceExporter(ConfigManager.getInstance());
        complianceService = new ComplianceService(persistenceService, auditLog,
                notificationService, containmentService, evidenceExporter, ConfigManager.getInstance());
        alertBus.subscribe(riskScorer);
        alertBus.subscribe(new AlertLogger());
        alertBus.subscribe(incidentManager);
        alertBus.subscribe(persistenceService);
        alertBus.subscribe(siemCorrelator);
        alertBus.subscribe(containmentService);
        alertBus.subscribe(notificationService);
    }

    public User login(String u, String p) {
        try {
            currentUser = authService.login(u, p);
            return currentUser;
        } catch (pk.ooad.ntd.domain.AuthenticationException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    public void start() {
        detectionEngine.start();
        trafficSimulator.start();
    }

    public void stop() {
        trafficSimulator.stop();
        detectionEngine.stop();
    }

    /**
     * Stops the pipeline and lets the durable store finish. Flows still open at
     * this point are closed first, so the last few connections are stored
     * instead of vanishing with the process.
     */
    public void shutdown() {
        stop();
        flowRecorder.closeAllOpen();
        mlFlowScorer.close();
        persistenceService.close();
    }

    public void reset() {
        stop();
        trafficSimulator.reset();
        detectionEngine.reset();
        flowRecorder.reset();
        mlFlowScorer.reset();
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
        int daysUnpatched = ConfigManager.getInstance().getInt("task.days.unpatched.default", 0);
        for (var asset : network.getAssets()) {
            if (asset.getStatus() != AssetStatus.COMPROMISED && asset.getStatus() != AssetStatus.SUSPICIOUS) {
                continue;
            }
            if (responseTasks.stream().anyMatch(task -> task.getTarget().getId().equals(asset.getId()))) {
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
        int daysUnpatched = ConfigManager.getInstance().getInt("task.days.unpatched.default", 0);
        for (var asset : view.getAssets()) {
            if (asset.getStatus() != AssetStatus.COMPROMISED && asset.getStatus() != AssetStatus.SUSPICIOUS) {
                continue;
            }
            if (responseTasks.stream().anyMatch(task -> task.getTarget().getId().equals(asset.getId()))) {
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

    public AlertQualityGate getAlertQualityGate() {
        return alertQualityGate;
    }

    public SiemCorrelator getSiemCorrelator() {
        return siemCorrelator;
    }

    public ContainmentService getContainmentService() {
        return containmentService;
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

    /**
     * Writes an evidence bundle from live and stored state. Stored rows are
     * preferred because they are the records the store still holds; when the
     * store is off the live ring is exported instead, and the manifest says so
     * by carrying the counts it actually wrote.
     */
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
        return evidenceExporter.export(actor, flows, alerts, auditLog.recent(auditCap), getIncidents());
    }
}
