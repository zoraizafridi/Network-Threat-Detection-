package pk.ooad.ntd.response;

import pk.ooad.ntd.domain.AnalystTeam;
import pk.ooad.ntd.domain.AssignmentResult;
import pk.ooad.ntd.domain.MitigationTask;
import pk.ooad.ntd.util.ConfigManager;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class AssignmentPlanner {
    public AssignmentResult plan(List<MitigationTask> tasks, List<AnalystTeam> teams) {
        Objects.requireNonNull(tasks, "tasks must not be null");
        Objects.requireNonNull(teams, "teams must not be null");
        List<AnalystTeam> teamList = List.copyOf(teams);
        if (teamList.size() > 4) {
            throw new IllegalArgumentException("Multiple-knapsack planning supports at most 4 teams");
        }
        if (teamList.stream().anyMatch(team -> team.getCapacity() < 0)) {
            throw new IllegalArgumentException("Team capacities must not be negative");
        }

        List<MitigationTask> orderedTasks = new ArrayList<>(tasks);
        orderedTasks.sort(Comparator.comparing(MitigationTask::getId));
        if (orderedTasks.stream().anyMatch(task -> task.getCost() < 0)) {
            throw new IllegalArgumentException("Mitigation task costs must not be negative");
        }
        List<MitigationTask> excluded = new ArrayList<>();
        List<MitigationTask> eligible = new ArrayList<>();
        int maxCapacity = teamList.stream().mapToInt(AnalystTeam::getCapacity).max().orElse(-1);
        for (MitigationTask task : orderedTasks) {
            if (teamList.isEmpty() || task.getCost() > maxCapacity) excluded.add(task);
            else eligible.add(task);
        }
        if (eligible.isEmpty()) return new AssignmentResult(Map.of(), 0, excluded, 0L);

        int[] capacities = teamList.stream().mapToInt(AnalystTeam::getCapacity).toArray();
        int[] multipliers = new int[capacities.length];
        int maxStates = ConfigManager.getInstance().getInt("dp.max.states", 2_000_000);
        if (maxStates < 1) {
            throw new IllegalArgumentException("dp.max.states must be at least 1");
        }
        long capacityStates = capacityStateCount(capacities, multipliers);
        long stateCount = Math.multiplyExact((long) eligible.size(), capacityStates);
        if (stateCount > maxStates) {
            throw new IllegalArgumentException("DP state count " + stateCount
                    + " exceeds configured dp.max.states=" + maxStates);
        }
        long tableSize = Math.multiplyExact((long) eligible.size() + 1L, capacityStates);
        if (tableSize > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("DP table requires " + tableSize
                    + " cells, which exceeds the supported flat-array size");
        }

        int[] values = new int[(int) tableSize];
        byte[] choices = new byte[(int) tableSize];
        buildTable(eligible, teamList, capacities, multipliers, (int) capacityStates, values, choices);
        Map<AnalystTeam, List<MitigationTask>> assignments = backtrack(
                eligible, teamList, capacities, multipliers, (int) capacityStates, values, choices);
        int fullCapacityState = (int) capacityStates - 1;
        int totalValue = values[eligible.size() * (int) capacityStates + fullCapacityState];
        return new AssignmentResult(assignments, totalValue, excluded, stateCount);
    }

    private void buildTable(List<MitigationTask> tasks, List<AnalystTeam> teams, int[] capacities,
                            int[] multipliers, int capacityStates, int[] values, byte[] choices) {
        for (int i = 1; i <= tasks.size(); i++) {
            MitigationTask task = tasks.get(i - 1);
            int previousOffset = (i - 1) * capacityStates;
            int currentOffset = i * capacityStates;
            System.arraycopy(values, previousOffset, values, currentOffset, capacityStates);
            for (int state = 0; state < capacityStates; state++) {
                for (int teamIndex = 0; teamIndex < teams.size(); teamIndex++) {
                    if (usedCapacity(state, teamIndex, capacities, multipliers) < task.getCost()) continue;
                    int previousState = state - task.getCost() * multipliers[teamIndex];
                    int candidateValue = Math.addExact(values[previousOffset + previousState], task.getValue());
                    int currentIndex = currentOffset + state;
                    byte existingChoice = choices[currentIndex];
                    byte candidateChoice = (byte) (teamIndex + 1);
                    if (candidateValue > values[currentIndex]
                            || (candidateValue == values[currentIndex] && existingChoice != 0
                            && candidateChoice < existingChoice)) {
                        values[currentIndex] = candidateValue;
                        choices[currentIndex] = candidateChoice;
                    }
                }
                if (values[previousOffset + state] == Integer.MIN_VALUE) {
                    values[currentOffset + state] = Integer.MIN_VALUE;
                }
            }
        }
    }

    private Map<AnalystTeam, List<MitigationTask>> backtrack(List<MitigationTask> tasks, List<AnalystTeam> teams,
                                                              int[] capacities, int[] multipliers,
                                                              int capacityStates, int[] values, byte[] choices) {
        Map<AnalystTeam, List<MitigationTask>> assignments = new LinkedHashMap<>();
        for (AnalystTeam team : teams) assignments.put(team, new ArrayList<>());
        int state = capacityStates - 1;
        for (int taskIndex = tasks.size(); taskIndex > 0; taskIndex--) {
            byte choice = choices[taskIndex * capacityStates + state];
            if (choice == 0) continue;
            int teamIndex = choice - 1;
            MitigationTask task = tasks.get(taskIndex - 1);
            assignments.get(teams.get(teamIndex)).add(task);
            state -= task.getCost() * multipliers[teamIndex];
        }
        for (List<MitigationTask> assigned : assignments.values()) {
            assigned.sort(Comparator.comparing(MitigationTask::getId));
        }
        assignments.entrySet().removeIf(entry -> entry.getValue().isEmpty());
        return assignments;
    }

    private long capacityStateCount(int[] capacities, int[] multipliers) {
        long count = 1L;
        for (int i = 0; i < capacities.length; i++) {
            if (count > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("DP capacity state product exceeds flat-array indexing limits");
            }
            multipliers[i] = (int) count;
            try {
                count = Math.multiplyExact(count, (long) capacities[i] + 1L);
            } catch (ArithmeticException e) {
                throw new IllegalArgumentException("DP capacity state product overflows supported limits", e);
            }
        }
        if (count > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("DP capacity state product exceeds flat-array indexing limits");
        }
        return count;
    }

    private int usedCapacity(int state, int teamIndex, int[] capacities, int[] multipliers) {
        int radix = capacities[teamIndex] + 1;
        return (state / multipliers[teamIndex]) % radix;
    }
}
