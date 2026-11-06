package pk.ooad.ntd.response;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.MitigationTask;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.Router;
import pk.ooad.ntd.domain.Server;
import pk.ooad.ntd.util.ConfigManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlannersTest {
    private static final ConfigManager CONFIG = ConfigManager.getInstance();

    @AfterEach
    void restoreConfig() {
        CONFIG.load("src/main/resources/config.properties");
    }

    @Test
    void unionFindMergesSetsAndRejectsInvalidIndexes() {
        UnionFind sets = new UnionFind(4);
        assertTrue(sets.union(0, 1));
        assertTrue(sets.union(1, 2));
        assertFalse(sets.union(0, 2));
        assertEquals(sets.find(0), sets.find(2));
        assertTrue(sets.union(2, 3));
        assertEquals(sets.find(0), sets.find(3));
        assertThrows(IndexOutOfBoundsException.class, () -> sets.find(4));
        assertThrows(IllegalArgumentException.class, () -> new UnionFind(-1));
        assertThrows(IndexOutOfBoundsException.class, () -> new UnionFind(0).union(0, 0));
    }

    @Test
    void backboneUsesRiskAndIdTieBreaksAndBaseCostOnly() {
        Network network = new Network();
        Router soc = new Router("soc", "SOC", "10.0.0.1", 5);
        Server a = new Server("a", "A", "10.0.0.2", 2);
        Server b = new Server("b", "B", "10.0.0.3", 2);
        Server c = new Server("c", "C", "10.0.0.4", 2);
        a.addRisk(20);
        b.addRisk(10);
        c.addRisk(10);
        List.of(soc, a, b, c).forEach(network::addAsset);
        Link highRisk = new Link("z-high", soc, a, 1, 10);
        Link idZ = new Link("z-id", soc, b, 1, 10);
        Link idA = new Link("a-id", soc, c, 1, 10);
        network.addLink(idZ);
        network.addLink(highRisk);
        network.addLink(idA);

        var result = new BackbonePlanner().plan(network);
        assertEquals(List.of(highRisk, idA, idZ), result.getChosenLinks());
        assertEquals(3.0, result.getTotalWeight());
        assertTrue(result.isConnected());
    }

    @Test
    void backboneReturnsSocComponentAndFullForestForDisconnectedInputs() {
        Network network = new Network();
        Router soc = new Router("soc", "SOC", "10.0.0.1", 5);
        Server a = new Server("a", "Alpha", "10.0.0.2", 1);
        Server b = new Server("b", "Beta", "10.0.0.3", 1);
        Server c = new Server("c", "Charlie", "10.0.0.4", 1);
        Server d = new Server("d", "Delta", "10.0.0.5", 1);
        List.of(soc, a, b, c, d).forEach(network::addAsset);
        Link socA = new Link("soc-a", soc, a, 1, 10);
        Link bC = new Link("b-c", b, c, 2, 10);
        network.addLink(socA);
        network.addLink(bC);

        var result = new BackbonePlanner().plan(network);
        assertFalse(result.isConnected());
        assertEquals(List.of(socA, bC), result.getChosenLinks());
        assertEquals(List.of(b, c, d), result.getUnreachable());
    }

    @Test
    void backboneUsesConfiguredSocHostInsteadOfDefaultRouter() throws IOException {
        Path config = Files.createTempFile("soc-host-config", ".properties");
        try {
            Files.writeString(config, "soc.host.id=alternate\n");
            CONFIG.load(config.toString());
            Network network = new Network();
            Router router = new Router("router", "Router", "10.0.0.1", 4);
            Server routerSide = new Server("router-side", "Router Side", "10.0.0.2", 1);
            Server alternate = new Server("alternate", "Alternate SOC", "10.0.0.3", 3);
            Server alternateSide = new Server("alternate-side", "Alternate Side", "10.0.0.4", 1);
            List.of(router, routerSide, alternate, alternateSide).forEach(network::addAsset);
            network.addLink(new Link("router-link", router, routerSide, 1, 10));
            network.addLink(new Link("alternate-link", alternate, alternateSide, 1, 10));

            var result = new BackbonePlanner().plan(network);
            assertFalse(result.isConnected());
            assertEquals(List.of(router, routerSide), result.getUnreachable());
        } finally {
            Files.deleteIfExists(config);
        }
    }

    @Test
    void backboneHandlesSingleHostTwoHostsAndAllCompromisedLinks() {
        BackbonePlanner planner = new BackbonePlanner();
        Network single = new Network();
        Router only = new Router("soc", "SOC", "10.0.0.1", 1);
        single.addAsset(only);
        assertTrue(planner.plan(single).isConnected());
        assertTrue(planner.plan(single).getUnreachable().isEmpty());

        Network two = new Network();
        Router soc = new Router("soc", "SOC", "10.0.0.1", 1);
        Server host = new Server("host", "Host", "10.0.0.2", 1);
        two.addAsset(soc);
        two.addAsset(host);
        Link link = new Link("link", soc, host, 3.5, 10);
        two.addLink(link);
        var twoResult = planner.plan(two);
        assertTrue(twoResult.isConnected());
        assertEquals(List.of(link), twoResult.getChosenLinks());
        assertEquals(3.5, twoResult.getTotalWeight());

        link.markCompromised();
        var compromisedResult = planner.plan(two);
        assertFalse(compromisedResult.isConnected());
        assertTrue(compromisedResult.getChosenLinks().isEmpty());
        assertEquals(List.of(host), compromisedResult.getUnreachable());
    }

    @Test
    void backboneSixHostExampleHasKnownTreeAndTotalAndIsDeterministic() {
        Network network = new Network();
        Router soc = new Router("soc", "SOC", "10.0.0.1", 5);
        List<NetworkAsset> hosts = new ArrayList<>();
        hosts.add(soc);
        for (int i = 1; i < 6; i++) hosts.add(new Server("h" + i, "Host " + i, "10.0.0." + (i + 1), 1));
        hosts.forEach(network::addAsset);
        List<Link> chain = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            Link link = new Link("chain-" + i, hosts.get(i), hosts.get(i + 1), i + 1, 10);
            chain.add(link);
            network.addLink(link);
        }
        network.addLink(new Link("cycle-1", hosts.get(0), hosts.get(2), 20, 10));
        network.addLink(new Link("cycle-2", hosts.get(1), hosts.get(4), 25, 10));

        BackbonePlanner planner = new BackbonePlanner();
        var first = planner.plan(network);
        var second = planner.plan(network);
        assertTrue(first.isConnected());
        assertEquals(chain, first.getChosenLinks());
        assertEquals(15.0, first.getTotalWeight());
        assertEquals(first.getChosenLinks(), second.getChosenLinks());
        assertEquals(first.getUnreachable(), second.getUnreachable());
        assertEquals(first.getTotalWeight(), second.getTotalWeight());
    }

    @Test
    void assignmentKnapsackEdgeCasesAndExclusionReturnBestPartialAllocation() {
        NetworkAsset target = new Server("target", "Target", "10.0.0.10", 1);
        AnalystTeam team = team("team", 3);
        MitigationTask small = task("small", target, 11, 2);
        MitigationTask betterFit = task("better", target, 19, 3);
        MitigationTask overCapacity = task("too-heavy", target, 900, 4);
        var result = new AssignmentPlanner().plan(List.of(small, betterFit, overCapacity), List.of(team));
        assertEquals(19, result.getTotalValue());
        assertEquals(List.of(overCapacity), result.getExcluded());
        assertEquals(List.of(betterFit), result.getAssignments().get(team));
        assertEquals(8L, result.getStateCount());

        var noTeams = new AssignmentPlanner().plan(List.of(small), List.of());
        assertEquals(0, noTeams.getTotalValue());
        assertEquals(List.of(small), noTeams.getExcluded());
        assertTrue(noTeams.getAssignments().isEmpty());

        var noTasks = new AssignmentPlanner().plan(List.of(), List.of(team));
        assertEquals(0, noTasks.getTotalValue());
        assertEquals(0L, noTasks.getStateCount());
        assertTrue(noTasks.getAssignments().isEmpty());
    }

    @Test
    void assignmentPlannerMatchesPlainKnapsackForOneTeam() {
        NetworkAsset target = new Server("target", "Target", "10.0.0.10", 1);
        AnalystTeam team = team("single", 8);
        List<MitigationTask> tasks = List.of(task("a", target, 10, 4), task("b", target, 9, 3),
                task("c", target, 8, 2), task("d", target, 4, 1));
        var result = new AssignmentPlanner().plan(tasks, List.of(team));
        assertEquals(23, result.getTotalValue());
        assertEquals(Set.of("a", "b", "d"), ids(result.getAssignments().get(team)));
    }

    @Test
    void assignmentPlannerSupportsThreeDistinctCapacitiesAndDeterministicSingleUse() {
        NetworkAsset target = new Server("target", "Target", "10.0.0.10", 1);
        AnalystTeam first = team("first", 3);
        AnalystTeam second = team("second", 5);
        AnalystTeam third = team("third", 7);
        List<MitigationTask> tasks = List.of(task("f", target, 40, 4), task("a", target, 20, 2),
                task("c", target, 30, 3), task("d", target, 50, 5), task("b", target, 10, 1));
        AssignmentPlanner planner = new AssignmentPlanner();
        var result1 = planner.plan(tasks, List.of(first, second, third));
        var result2 = planner.plan(tasks, List.of(first, second, third));
        assertEquals(150, result1.getTotalValue());
        assertEquals(result1.getTotalValue(), result2.getTotalValue());
        assertEquals(idsFor(result1), idsFor(result2));
        Set<String> assignedIds = new HashSet<>();
        result1.getAssignments().forEach((team, assigned) -> {
            assertTrue(assigned.stream().map(MitigationTask::getCost).mapToInt(Integer::intValue).sum() <= team.getCapacity());
            assigned.forEach(task -> assertTrue(assignedIds.add(task.getId()), "task assigned more than once"));
        });
    }

    @Test
    void assignmentPlannerPrefersSkipThenLowestTeamIndexOnTies() {
        NetworkAsset target = new Server("target", "Target", "10.0.0.10", 1);
        AnalystTeam first = team("first", 2);
        AnalystTeam second = team("second", 2);
        MitigationTask task = task("equal", target, 10, 2);
        var assigned = new AssignmentPlanner().plan(List.of(task), List.of(first, second));
        assertEquals(List.of(task), assigned.getAssignments().get(first));
        assertFalse(assigned.getAssignments().containsKey(second));
        MitigationTask zero = task("zero", target, 0, 1);
        var skipped = new AssignmentPlanner().plan(List.of(zero), List.of(first));
        assertTrue(skipped.getAssignments().isEmpty());
    }

    @Test
    void assignmentPlannerGuardsConfiguredStateLimit() throws IOException {
        Path config = Files.createTempFile("dp-config", ".properties");
        try {
            Files.writeString(config, "dp.max.states=4\n");
            CONFIG.load(config.toString());
            NetworkAsset target = new Server("target", "Target", "10.0.0.10", 1);
            AnalystTeam team = team("team", 2);
            List<MitigationTask> tasks = List.of(task("a", target, 1, 1), task("b", target, 1, 1));
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> new AssignmentPlanner().plan(tasks, List.of(team)));
            assertTrue(error.getMessage().contains("dp.max.states"));
        } finally {
            Files.deleteIfExists(config);
        }
    }

    @Test
    void randomizedMultipleKnapsackMatchesBruteForceForTwoHundredSeededCases() {
        Random random = new Random(982451653L);
        NetworkAsset target = new Server("target", "Target", "10.0.0.10", 1);
        for (int caseIndex = 0; caseIndex < 200; caseIndex++) {
            int taskCount = random.nextInt(9);
            int teamCount = 1 + random.nextInt(4);
            List<AnalystTeam> teams = randomTeams(random, teamCount);
            List<MitigationTask> tasks = new ArrayList<>();
            for (int i = 0; i < taskCount; i++) {
                tasks.add(task("task-" + i, target, random.nextInt(101), random.nextInt(9)));
            }
            int expected = bruteForce(tasks, teams, 0, teams.stream().mapToInt(AnalystTeam::getCapacity).toArray());
            var actual = new AssignmentPlanner().plan(tasks, teams);
            assertEquals(expected, actual.getTotalValue(), "seeded case " + caseIndex);
                Set<MitigationTask> assignedTasks = new HashSet<>();
                for (Map.Entry<AnalystTeam, List<MitigationTask>> entry : actual.getAssignments().entrySet()) {
                int assignedCost = entry.getValue().stream().mapToInt(MitigationTask::getCost).sum();
                assertTrue(assignedCost <= entry.getKey().getCapacity(),
                    "assigned cost exceeds team capacity in seeded case " + caseIndex);
                for (MitigationTask assignedTask : entry.getValue()) {
                    assertTrue(assignedTasks.add(assignedTask),
                        "task appears in more than one team list in seeded case " + caseIndex);
                }
                }
                assertTrue(actual.getExcluded().stream().noneMatch(assignedTasks::contains),
                    "task is both assigned and excluded in seeded case " + caseIndex);
                int assignedValue = actual.getAssignments().values().stream().flatMap(List::stream)
                    .mapToInt(MitigationTask::getValue).sum();
                assertEquals(actual.getTotalValue(), assignedValue,
                    "assigned task values do not equal totalValue in seeded case " + caseIndex);
        }
    }

    @Test
    void assignmentPlannerRejectsInvalidInputsAndSupportsMoreDemandThanCapacity() {
        AssignmentPlanner planner = new AssignmentPlanner();
        assertThrows(NullPointerException.class, () -> planner.plan(null, List.of()));
        assertThrows(NullPointerException.class, () -> planner.plan(List.of(), null));
        NetworkAsset target = new Server("target", "Target", "10.0.0.10", 1);
        assertThrows(IllegalArgumentException.class,
                () -> planner.plan(List.of(task("negative", target, 1, -1)), List.of(team("t", 1))));
        assertThrows(IllegalArgumentException.class, () -> planner.plan(List.of(),
                List.of(team("1", 1), team("2", 2), team("3", 3), team("4", 4), team("5", 5))));
    }

    private static int bruteForce(List<MitigationTask> tasks, List<AnalystTeam> teams, int index, int[] remaining) {
        if (index == tasks.size()) return 0;
        int best = bruteForce(tasks, teams, index + 1, remaining);
        MitigationTask task = tasks.get(index);
        for (int teamIndex = 0; teamIndex < teams.size(); teamIndex++) {
            if (task.getCost() <= remaining[teamIndex]) {
                remaining[teamIndex] -= task.getCost();
                best = Math.max(best, task.getValue() + bruteForce(tasks, teams, index + 1, remaining));
                remaining[teamIndex] += task.getCost();
            }
        }
        return best;
    }

    private static List<AnalystTeam> randomTeams(Random random, int count) {
        List<Integer> capacities = new ArrayList<>();
        while (capacities.size() < count) {
            int capacity = 1 + random.nextInt(10);
            if (!capacities.contains(capacity)) capacities.add(capacity);
        }
        return capacities.stream().map(capacity -> team("team-" + capacity, capacity)).toList();
    }

    private static MitigationTask task(String id, NetworkAsset target, int value, int cost) {
        return new MitigationTask(id, target, value, cost, "ignored");
    }

    private static AnalystTeam team(String id, int capacity) {
        return new AnalystTeam(id, id, Set.of(), capacity, true);
    }

    private static Set<String> ids(List<MitigationTask> tasks) {
        return tasks.stream().map(MitigationTask::getId).collect(java.util.stream.Collectors.toSet());
    }

    private static List<String> idsFor(pk.ooad.ntd.domain.AssignmentResult result) {
        return result.getAssignments().entrySet().stream()
                .sorted(Comparator.comparing(entry -> entry.getKey().getId()))
                .flatMap(entry -> entry.getValue().stream().map(MitigationTask::getId))
                .toList();
    }
}
