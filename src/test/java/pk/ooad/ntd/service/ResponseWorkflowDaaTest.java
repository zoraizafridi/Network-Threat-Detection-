package pk.ooad.ntd.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.AssetStatus;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.MitigationTask;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.ResponsePlan;
import pk.ooad.ntd.domain.Router;
import pk.ooad.ntd.domain.Server;
import pk.ooad.ntd.response.BackbonePlanner;
import pk.ooad.ntd.util.ConfigManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseWorkflowDaaTest {
    private final ConfigManager config = ConfigManager.getInstance();
    private Path configFile;

    @AfterEach
    void restoreConfig() throws IOException {
        if (configFile != null) Files.deleteIfExists(configFile);
        config.reload();
    }

    @Test
    void twelveHostTwentyTwoLinkExampleRunsBackboneThenDecayedAssignment() throws IOException {
        configure();
        Network network = buildTwelveHostNetwork();
        List<AnalystTeam> teams = teams();
        List<MitigationTask> tasks = tasksFor(network);
        ResponsePlan result = facade(network, tasks, teams).runResponse();

        assertTrue(result.getBackbone().isConnected());
        assertEquals(22, network.getLinks().size());
        assertEquals(chainLinkIds(11), linkIds(result.getBackbone().getChosenLinks()));
        assertEquals(66.0, result.getBackbone().getTotalWeight());
        assertEquals(290, result.getAssignment().getTotalValue());
        assertEquals(List.of("task-host-01", "task-host-02", "task-host-10"),
                assignedIds(result.getAssignment()));
        MitigationTask decayed = result.getAssignment().getAssignments().values().stream()
                .flatMap(List::stream).filter(task -> task.getId().equals("task-host-10")).findFirst().orElseThrow();
        assertEquals(120, decayed.getValue());
    }

    @Test
    void removingTwoHighestRiskNonSocHostsChangesBackboneAndAssignment() throws IOException {
        configure();
        Network initial = buildTwelveHostNetwork();
        ResponsePlan before = facade(initial, tasksFor(initial), teams()).runResponse();
        assertEquals(290, before.getAssignment().getTotalValue());

        Network reduced = buildTwelveHostNetwork();
        List<MitigationTask> tasksBeforeRemoval = tasksFor(reduced);
        assertTrue(reduced.removeAsset("host-10"));
        assertTrue(reduced.removeAsset("host-11"));
        ResponsePlan after = facade(reduced, tasksBeforeRemoval, teams()).runResponse();

        assertTrue(after.getBackbone().isConnected());
        assertEquals(chainLinkIds(9), linkIds(after.getBackbone().getChosenLinks()));
        assertEquals(45.0, after.getBackbone().getTotalWeight());
        assertEquals(200, after.getAssignment().getTotalValue());
        assertEquals(List.of("task-host-01", "task-host-02", "task-host-03"), assignedIds(after.getAssignment()));
        assertFalse(linkIds(after.getBackbone().getChosenLinks()).equals(linkIds(before.getBackbone().getChosenLinks())));
    }

    @Test
    void facadeDoesNotAssignTasksOutsideTheSocComponent() throws IOException {
        configure();
        Network network = new Network();
        NetworkAsset soc = new Router("soc", "SOC", "10.0.0.1", 5);
        NetworkAsset reachable = new Server("reachable", "Reachable", "10.0.0.2", 2);
        NetworkAsset unreachable = new Server("unreachable", "Unreachable", "10.0.0.3", 2);
        network.addAsset(soc);
        network.addAsset(reachable);
        network.addAsset(unreachable);
        network.addLink(new Link("soc-reachable", soc, reachable, 1, 10));
        unreachable.addRisk(80);
        unreachable.setStatus(AssetStatus.COMPROMISED);
        MitigationTask reachableTask = task("reachable-task", reachable, 25, 1, 0);

        ResponsePlan response = facade(network, List.of(reachableTask), teams()).runResponse();
        assertFalse(response.getBackbone().isConnected());
        assertEquals(List.of(unreachable), response.getBackbone().getUnreachable());
        assertEquals(25, response.getAssignment().getTotalValue());
        assertEquals(List.of("reachable-task"), assignedIds(response.getAssignment()));
    }

        @Test
        void facadeCreatesConfiguredTasksForCompromisedAndSuspiciousHostsOnly() throws IOException {
        configureTaskCosts();
        Network network = new Network();
        NetworkAsset soc = new Router("soc", "SOC", "10.0.0.1", 5);
        NetworkAsset compromisedServer = new Server("server", "Server", "10.0.0.2", 2);
        NetworkAsset compromisedWorkstation = new pk.ooad.ntd.domain.Workstation(
            "workstation", "Workstation", "10.0.0.3", 3, "analyst");
        NetworkAsset suspiciousIot = new pk.ooad.ntd.domain.IoTDevice(
            "iot", "IoT", "10.0.0.4", 2, "1.0", false);
        NetworkAsset normalHost = new Server("normal", "Normal", "10.0.0.5", 4);
        List.of(soc, compromisedServer, compromisedWorkstation, suspiciousIot, normalHost)
            .forEach(network::addAsset);
        compromisedServer.addRisk(40);
        compromisedServer.setStatus(AssetStatus.COMPROMISED);
        compromisedWorkstation.addRisk(50);
        compromisedWorkstation.setStatus(AssetStatus.COMPROMISED);
        suspiciousIot.addRisk(30);
        suspiciousIot.setStatus(AssetStatus.SUSPICIOUS);
        normalHost.addRisk(99);
        network.addLink(new Link("soc-server", soc, compromisedServer, 1, 10));
        network.addLink(new Link("soc-workstation", soc, compromisedWorkstation, 1, 10));
        network.addLink(new Link("soc-iot", soc, suspiciousIot, 1, 10));
        network.addLink(new Link("soc-normal", soc, normalHost, 1, 10));
        List<AnalystTeam> teams = List.of(new AnalystTeam("capacity", "Capacity", Set.of(), 20, true));

        ResponsePlan result = facade(network, List.of(), teams).runResponse();
        List<MitigationTask> assigned = result.getAssignment().getAssignments().values().stream()
            .flatMap(List::stream).toList();
        assertEquals(3, assigned.size());
        assertEquals(377, result.getAssignment().getTotalValue());
        assertEquals(104, findTask(assigned, "risk-server").getValue());
        assertEquals(8, findTask(assigned, "risk-server").getCost());
        assertEquals(3, findTask(assigned, "risk-server").getDaysUnpatched());
        assertEquals(195, findTask(assigned, "risk-workstation").getValue());
        assertEquals(6, findTask(assigned, "risk-workstation").getCost());
        assertEquals(78, findTask(assigned, "risk-iot").getValue());
        assertEquals(4, findTask(assigned, "risk-iot").getCost());
        assertFalse(assigned.stream().anyMatch(task -> task.getTarget().equals(normalHost)));
        }

        @Test
        void facadeReturnsEmptyAssignmentForNormalOrEmptyNetworks() throws IOException {
        configure();
        Network normalNetwork = new Network();
        NetworkAsset soc = new Router("soc", "SOC", "10.0.0.1", 5);
        NetworkAsset normal = new Server("normal", "Normal", "10.0.0.2", 2);
        normalNetwork.addAsset(soc);
        normalNetwork.addAsset(normal);
        normalNetwork.addLink(new Link("normal-link", soc, normal, 1, 10));
        ResponsePlan normalResult = facade(normalNetwork, List.of(), teams()).runResponse();
        assertTrue(normalResult.getAssignment().getAssignments().isEmpty());
        assertEquals(0, normalResult.getAssignment().getTotalValue());

        ResponsePlan emptyResult = facade(new Network(), List.of(), teams()).runResponse();
        assertTrue(emptyResult.getAssignment().getAssignments().isEmpty());
        assertEquals(0, emptyResult.getAssignment().getTotalValue());
        }

    private void configure() throws IOException {
        configFile = Files.createTempFile("response-flow", ".properties");
        Files.writeString(configFile, "decay.rate=0.1\nsoc.host.id=\ndp.max.states=2000000\n");
        config.load(configFile.toString());
    }

    private void configureTaskCosts() throws IOException {
        configFile = Files.createTempFile("response-task-costs", ".properties");
        Files.writeString(configFile, "decay.rate=0.1\nsoc.host.id=\ndp.max.states=2000000\n"
                + "task.cost.server=8\ntask.cost.workstation=6\ntask.cost.router=12\ntask.cost.iot=4\n"
                + "task.days.unpatched.default=3\n");
        config.load(configFile.toString());
    }

    private IncidentResponseFacade facade(Network network, List<MitigationTask> tasks, List<AnalystTeam> teams) {
        return new IncidentResponseFacade(network, 19L, tasks, teams);
    }

    private Network buildTwelveHostNetwork() {
        Network network = new Network();
        NetworkAsset soc = new Router("soc", "SOC", "10.0.0.1", 5);
        network.addAsset(soc);
        List<NetworkAsset> hosts = new ArrayList<>();
        hosts.add(soc);
        for (int i = 1; i < 12; i++) {
            String suffix = String.format("%02d", i);
            NetworkAsset host = new Server("host-" + suffix, "Host " + suffix,
                    "10.0.0." + (i + 1), 2);
            if (i == 10) host.addRisk(95);
            if (i == 11) host.addRisk(90);
            hosts.add(host);
            network.addAsset(host);
        }
        for (int i = 0; i < 11; i++) {
            network.addLink(new Link(String.format("chain-%02d", i + 1), hosts.get(i), hosts.get(i + 1), i + 1, 10));
        }
        int[][] extraEdges = {
                {0, 2}, {0, 3}, {1, 3}, {2, 4}, {3, 5}, {4, 6},
                {5, 7}, {6, 8}, {7, 9}, {8, 10}, {9, 11}
        };
        for (int i = 0; i < extraEdges.length; i++) {
            network.addLink(new Link(String.format("extra-%02d", i + 1),
                    hosts.get(extraEdges[i][0]), hosts.get(extraEdges[i][1]), 20 + i, 10));
        }
        return network;
    }

    private List<AnalystTeam> teams() {
        return List.of(
                new AnalystTeam("team-6", "Team 6", Set.of(), 6, true),
                new AnalystTeam("team-4", "Team 4", Set.of(), 4, true),
                new AnalystTeam("team-3", "Team 3", Set.of(), 3, true));
    }

    private List<MitigationTask> tasksFor(Network network) {
        return List.of(
                task("task-host-01", network.getAsset("host-01"), 100, 4, 0),
                task("task-host-02", network.getAsset("host-02"), 70, 3, 0),
                task("task-host-03", network.getAsset("host-03"), 30, 2, 0),
                task("task-host-10", network.getAsset("host-10"), 100, 6, 2),
                task("task-host-11", network.getAsset("host-11"), 40, 3, 0));
    }

    private MitigationTask task(String id, NetworkAsset target, int value, int cost, int daysUnpatched) {
        return new MitigationTask(id, target, value, cost, "", daysUnpatched);
    }

    private MitigationTask findTask(List<MitigationTask> tasks, String id) {
        return tasks.stream().filter(task -> task.getId().equals(id)).findFirst().orElseThrow();
    }

    private List<String> chainLinkIds(int count) {
        List<String> ids = new ArrayList<>();
        for (int i = 1; i <= count; i++) ids.add(String.format("chain-%02d", i));
        return ids;
    }

    private List<String> linkIds(List<Link> links) {
        return links.stream().map(Link::getId).toList();
    }

    private List<String> assignedIds(pk.ooad.ntd.domain.AssignmentResult result) {
        return result.getAssignments().values().stream().flatMap(List::stream)
                .map(MitigationTask::getId).sorted().toList();
    }
}
