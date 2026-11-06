package pk.ooad.ntd.response;

import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.AssignmentResult;
import pk.ooad.ntd.domain.MitigationTask;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class AssignmentPlanner {
    public AssignmentResult plan(List<MitigationTask> tasks, List<AnalystTeam> teams) {
        Objects.requireNonNull(tasks, "tasks must not be null");
        Objects.requireNonNull(teams, "teams must not be null");
        List<MitigationTask> taskList = List.copyOf(tasks);
        if (taskList.stream().anyMatch(task -> task.getCost() < 0)) {
            throw new IllegalArgumentException("Mitigation task costs must not be negative");
        }
        List<AnalystTeam> availableTeams = teams.stream().filter(AnalystTeam::isAvailable).toList();
        int stateCount = stateCount(availableTeams);
        int[][] table = buildTable(taskList, availableTeams, stateCount);
        Map<AnalystTeam, List<MitigationTask>> assignments = backtrack(taskList, availableTeams, table, stateCount);
        int total = assignments.values().stream().flatMap(List::stream).mapToInt(MitigationTask::getValue).sum();
        return new AssignmentResult(assignments, total, table);
    }

    private int[][] buildTable(List<MitigationTask> tasks, List<AnalystTeam> teams, int stateCount) {
        int[][] table = new int[tasks.size() + 1][stateCount];
        for (int[] row : table) java.util.Arrays.fill(row, Integer.MIN_VALUE);
        table[0][0] = 0;
        int[] multipliers = multipliers(teams);
        for (int taskIndex = 0; taskIndex < tasks.size(); taskIndex++) {
            MitigationTask task = tasks.get(taskIndex);
            for (int state = 0; state < stateCount; state++) {
                int currentValue = table[taskIndex][state];
                if (currentValue == Integer.MIN_VALUE) continue;
                table[taskIndex + 1][state] = Math.max(table[taskIndex + 1][state], currentValue);
                for (int teamIndex = 0; teamIndex < teams.size(); teamIndex++) {
                    AnalystTeam team = teams.get(teamIndex);
                    if (!team.canHandle(task) || usedCapacity(state, teamIndex, teams, multipliers) + task.getCost() > team.getCapacity()) {
                        continue;
                    }
                    int nextState = state + task.getCost() * multipliers[teamIndex];
                    table[taskIndex + 1][nextState] = Math.max(table[taskIndex + 1][nextState], currentValue + task.getValue());
                }
            }
        }
        return table;
    }

    private Map<AnalystTeam, List<MitigationTask>> backtrack(List<MitigationTask> tasks, List<AnalystTeam> teams,
                                                             int[][] table, int stateCount) {
        Map<AnalystTeam, List<MitigationTask>> result = new LinkedHashMap<>();
        for (AnalystTeam team : teams) result.put(team, new ArrayList<>());
        int[] multipliers = multipliers(teams);
        int bestState = 0;
        int bestValue = 0;
        for (int state = 0; state < stateCount; state++) {
            int value = table[tasks.size()][state];
            if (value > bestValue) {
                bestValue = value;
                bestState = state;
            }
        }
        int state = bestState;
        for (int taskIndex = tasks.size() - 1; taskIndex >= 0; taskIndex--) {
            int value = table[taskIndex + 1][state];
            if (table[taskIndex][state] == value) continue;
            MitigationTask task = tasks.get(taskIndex);
            boolean assigned = false;
            for (int teamIndex = teams.size() - 1; teamIndex >= 0; teamIndex--) {
                int step = task.getCost() * multipliers[teamIndex];
                int previousState = state - step;
                if (previousState >= 0 && table[taskIndex][previousState] != Integer.MIN_VALUE
                        && table[taskIndex][previousState] + task.getValue() == value
                        && teams.get(teamIndex).canHandle(task)) {
                    result.get(teams.get(teamIndex)).add(task);
                    state = previousState;
                    assigned = true;
                    break;
                }
            }
            if (!assigned && table[taskIndex][state] != value) {
                throw new IllegalStateException("Unable to reconstruct task assignment");
            }
        }
        for (List<MitigationTask> assignedTasks : result.values()) Collections.reverse(assignedTasks);
        result.entrySet().removeIf(entry -> entry.getValue().isEmpty());
        return result;
    }

    private int stateCount(List<AnalystTeam> teams) {
        long count = 1;
        for (AnalystTeam team : teams) {
            count *= (long) team.getCapacity() + 1L;
            if (team.getCapacity() < 0 || count > 1_000_000L) {
                throw new IllegalArgumentException("Combined analyst capacity is too large for the DP table");
            }
        }
        return (int) count;
    }

    private int[] multipliers(List<AnalystTeam> teams) {
        int[] result = new int[teams.size()];
        long multiplier = 1;
        for (int i = 0; i < teams.size(); i++) {
            result[i] = (int) multiplier;
            multiplier *= (long) teams.get(i).getCapacity() + 1L;
        }
        return result;
    }

    private int usedCapacity(int state, int teamIndex, List<AnalystTeam> teams, int[] multipliers) {
        int radix = teams.get(teamIndex).getCapacity() + 1;
        return (state / multipliers[teamIndex]) % radix;
    }
}
