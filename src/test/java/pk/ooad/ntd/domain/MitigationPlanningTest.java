package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MitigationPlanningTest {

    @Test
    @DisplayName("MitigationTask: Instantiation, getters, and equality")
    void testMitigationTask() {
        Server server = new Server("srv-1", "Web Server", "10.0.0.1", 4);
        MitigationTask task = new MitigationTask("task-1", server, 100, 20, "FIREWALL_CONFIG");

        assertEquals("task-1", task.getId());
        assertEquals(server, task.getTarget());
        assertEquals(100, task.getValue());
        assertEquals(20, task.getCost());
        assertEquals("FIREWALL_CONFIG", task.getRequiredSkill());

        MitigationTask sameId = new MitigationTask("task-1", server, 50, 10, "OTHER");
        MitigationTask diffId = new MitigationTask("task-2", server, 100, 20, "FIREWALL_CONFIG");

        assertEquals(task, sameId);
        assertEquals(task.hashCode(), sameId.hashCode());
        assertNotEquals(task, diffId);
        assertNotEquals(task, null);
        assertNotNull(task.toString());

        assertThrows(NullPointerException.class, () ->
            new MitigationTask(null, server, 10, 5, "SKILL")
        );
        assertThrows(NullPointerException.class, () ->
            new MitigationTask("t", null, 10, 5, "SKILL")
        );
    }

    @Test
    @DisplayName("AnalystTeam: canHandle skill, capacity, availability logic and edge cases")
    void testAnalystTeamCanHandle() {
        AnalystTeam team = new AnalystTeam("team-1", "Alpha Team", Set.of("MALWARE_ANALYSIS", "FIREWALL_CONFIG"), 40, true);
        Server server = new Server("srv-1", "Web Server", "10.0.0.1", 4);

        MitigationTask manageableTask = new MitigationTask("t1", server, 100, 30, "FIREWALL_CONFIG");
        assertTrue(team.canHandle(manageableTask), "Team with skill, capacity, and availability can handle task");

        // General task with no specific skill requirement
        MitigationTask noSkillTask = new MitigationTask("t2", server, 50, 15, "");
        assertTrue(team.canHandle(noSkillTask));

        MitigationTask nullSkillTask = new MitigationTask("t3", server, 50, 15, null);
        assertTrue(team.canHandle(nullSkillTask));

        // Missing required skill
        MitigationTask unhandledSkillTask = new MitigationTask("t4", server, 80, 20, "REVERSE_ENGINEERING");
        assertFalse(team.canHandle(unhandledSkillTask), "Missing required skill must return false");

        // Cost exceeds capacity
        MitigationTask tooCostlyTask = new MitigationTask("t5", server, 200, 50, "FIREWALL_CONFIG");
        assertFalse(team.canHandle(tooCostlyTask), "Cost exceeding capacity must return false");

        // Team unavailable
        team.setAvailable(false);
        assertFalse(team.canHandle(manageableTask), "Unavailable team cannot handle any task");

        // Null task
        assertFalse(team.canHandle(null), "Null task must return false");

        // Team mutations
        team.setAvailable(true);
        team.setCapacity(100);
        team.addSkill("REVERSE_ENGINEERING");
        assertTrue(team.canHandle(unhandledSkillTask));
        assertTrue(team.canHandle(tooCostlyTask));

        // Team equality and toString
        AnalystTeam sameTeam = new AnalystTeam("team-1", "Different Name", Set.of(), 10, false);
        assertEquals(team, sameTeam);
        assertEquals(team.hashCode(), sameTeam.hashCode());
        assertNotNull(team.toString());
    }

    @Test
    @DisplayName("BackboneResult, AssignmentResult, and ResponsePlan compositions")
    void testResponsePlanAndResults() {
        Server s1 = new Server("s1", "S1", "10.0.0.1", 2);
        Server s2 = new Server("s2", "S2", "10.0.0.2", 2);
        Router r1 = new Router("r1", "R1", "10.0.0.254", 4);
        Link l1 = new Link("l1", s1, r1, 1.0, 100.0);

        BackboneResult backbone = new BackboneResult(List.of(l1), 1.0, true, List.of(s2));
        assertEquals(1, backbone.getChosenLinks().size());
        assertEquals(1.0, backbone.getTotalWeight());
        assertTrue(backbone.isConnected());
        assertEquals(1, backbone.getUnreachable().size());
        assertTrue(backbone.getUnreachable().contains(s2));
        assertNotNull(backbone.toString());

        AnalystTeam team = new AnalystTeam("team-1", "Alpha", Set.of("SKILL_A"), 50, true);
        MitigationTask task = new MitigationTask("t1", s1, 90, 20, "SKILL_A");
        int[][] dpTable = new int[][]{{0, 0}, {0, 90}};
        AssignmentResult assignment = new AssignmentResult(Map.of(team, List.of(task)), 90, dpTable);

        assertEquals(1, assignment.getAssignments().size());
        assertEquals(90, assignment.getTotalValue());
        assertEquals(dpTable, assignment.getDpTable());
        assertNotNull(assignment.toString());

        // ResponsePlan composition
        ResponsePlan plan = new ResponsePlan(backbone, assignment);
        assertEquals(backbone, plan.getBackbone());
        assertEquals(assignment, plan.getAssignment());
        assertNotNull(plan.toString());

        assertThrows(NullPointerException.class, () -> new ResponsePlan(null, assignment));
        assertThrows(NullPointerException.class, () -> new ResponsePlan(backbone, null));
    }
}

