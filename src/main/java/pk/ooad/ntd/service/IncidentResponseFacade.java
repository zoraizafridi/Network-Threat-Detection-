package pk.ooad.ntd.service;

import pk.ooad.ntd.detection.AlertBus;
import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.detection.DetectionEngine;
import pk.ooad.ntd.detection.Detector;
import pk.ooad.ntd.detection.DetectorFactory;
import pk.ooad.ntd.domain.Admin;
import pk.ooad.ntd.domain.AnalystTeam;
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
        this(network, seed, List.of(), null);
    }

    IncidentResponseFacade(Network network, long seed, List<MitigationTask> tasks, List<AnalystTeam> teams) {
        this.network = Objects.requireNonNull(network, "network must not be null");
        responseTasks = tasks == null ? List.of() : List.copyOf(tasks);
        responseTeams = teams == null ? null : List.copyOf(teams);
        trafficSimulator = new TrafficSimulator(network, seed);
        alertBus = new AlertBus();
        detectionEngine = new DetectionEngine(trafficSimulator.getEventQueue(), alertBus,
                ConfigManager.getInstance().getInt("detection.cooldownSeconds", 5));
        for (Detector detector : new DetectorFactory().createAll()) detectionEngine.addDetector(detector);
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
        alertBus.subscribe(riskScorer);
        alertBus.subscribe(new AlertLogger());
        alertBus.subscribe(incidentManager);
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

    public void reset() {
        stop();
        trafficSimulator.reset();
        detectionEngine.reset();
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
}
