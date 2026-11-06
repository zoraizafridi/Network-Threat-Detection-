package pk.ooad.ntd.response;

import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.MitigationTask;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.Server;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlannersTest {
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
    void backboneHandlesEmptySingleConnectedAndDisconnectedNetworks() {
        BackbonePlanner planner = new BackbonePlanner();
        var empty = planner.plan(new Network());
        assertTrue(empty.isConnected());
        assertTrue(empty.getChosenLinks().isEmpty());
        assertTrue(empty.getUnreachable().isEmpty());

        Network oneNode = new Network();
        NetworkAsset only = new Server("one", "one", "10.0.0.1", 1);
        oneNode.addAsset(only);
        assertTrue(planner.plan(oneNode).isConnected());
        assertTrue(planner.plan(oneNode).getUnreachable().isEmpty());

        Network disconnected = new Network();
        NetworkAsset a = new Server("a", "A", "10.0.0.1", 1);
        NetworkAsset b = new Server("b", "B", "10.0.0.2", 1);
        NetworkAsset c = new Server("c", "C", "10.0.0.3", 1);
        disconnected.addAsset(a);
        disconnected.addAsset(b);
        disconnected.addAsset(c);
        disconnected.addLink(new Link("ab", a, b, 4.0, 10.0));
        var result = planner.plan(disconnected);
        assertFalse(result.isConnected());
        assertEquals(List.of(c), result.getUnreachable());
        assertEquals(1, result.getChosenLinks().size());
    }

    @Test
    void backboneUsesMinimumWeightTreeAndSkipsCompromisedLinks() {
        Network network = new Network();
        NetworkAsset a = new Server("a", "A", "10.0.0.1", 1);
        NetworkAsset b = new Server("b", "B", "10.0.0.2", 1);
        NetworkAsset c = new Server("c", "C", "10.0.0.3", 1);
        network.addAsset(a);
        network.addAsset(b);
        network.addAsset(c);
        Link ab = new Link("ab", a, b, 5.0, 10.0);
        Link bc = new Link("bc", b, c, 2.0, 10.0);
        Link ac = new Link("ac", a, c, 1.0, 10.0);
        network.addLink(ab);
        network.addLink(bc);
        network.addLink(ac);
        ac.markCompromised();
        var result = new BackbonePlanner().plan(network);
        assertTrue(result.isConnected());
        assertEquals(List.of(bc, ab), result.getChosenLinks());
        assertEquals(7.0, result.getTotalWeight());
    }

    @Test
    void assignmentPlannerUsesDpAndHonorsSkillsAndTeamCapacities() {
        NetworkAsset target = new Server("target", "Target", "10.0.0.10", 2);
        MitigationTask valuable = new MitigationTask("valuable", target, 100, 4, "network");
        MitigationTask second = new MitigationTask("second", target, 70, 3, "forensics");
        MitigationTask impossible = new MitigationTask("impossible", target, 1000, 1, "missing");
        AnalystTeam networkTeam = new AnalystTeam("n", "Network", Set.of("network"), 4, true);
        AnalystTeam forensicTeam = new AnalystTeam("f", "Forensics", Set.of("forensics"), 3, true);

        var result = new AssignmentPlanner().plan(List.of(valuable, second, impossible), List.of(networkTeam, forensicTeam));
        assertEquals(170, result.getTotalValue());
        assertEquals(List.of(valuable), result.getAssignments().get(networkTeam));
        assertEquals(List.of(second), result.getAssignments().get(forensicTeam));
        assertEquals(4, result.getDpTable().length);
        assertThrows(UnsupportedOperationException.class,
                () -> result.getAssignments().put(networkTeam, List.of(impossible)));

        var empty = new AssignmentPlanner().plan(List.of(), List.of());
        assertEquals(0, empty.getTotalValue());
        assertEquals(1, empty.getDpTable().length);
        assertEquals(1, empty.getDpTable()[0].length);
        assertTrue(empty.getAssignments().isEmpty());

        MitigationTask negativeCost = new MitigationTask("negative", target, 10, -1, "network");
        assertThrows(IllegalArgumentException.class,
            () -> new AssignmentPlanner().plan(List.of(negativeCost), List.of(networkTeam)));
    }

    @Test
    void assignmentPlannerRejectsNullInputsAndOversizedTables() {
        AssignmentPlanner planner = new AssignmentPlanner();
        assertThrows(NullPointerException.class, () -> planner.plan(null, List.of()));
        assertThrows(NullPointerException.class, () -> planner.plan(List.of(), null));
        AnalystTeam oversized = new AnalystTeam("large", "Large", Set.of(), 1_000_000, true);
        assertThrows(IllegalArgumentException.class, () -> planner.plan(List.of(), List.of(oversized)));
    }
}
