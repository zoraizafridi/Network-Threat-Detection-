package pk.ooad.ntd.domain;

import java.util.Collections;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class AssignmentResult {
    private final Map<AnalystTeam, List<MitigationTask>> assignments;
    private final int totalValue;
    private final List<MitigationTask> excluded;
    private final long stateCount;

    public AssignmentResult(Map<AnalystTeam, List<MitigationTask>> assignments, int totalValue,
                            List<MitigationTask> excluded, long stateCount) {
        this.assignments = assignments != null ? new LinkedHashMap<>(assignments) : new LinkedHashMap<>();
        this.assignments.replaceAll((team, tasks) -> tasks != null ? List.copyOf(tasks) : List.of());
        this.totalValue = totalValue;
        this.excluded = excluded != null ? new ArrayList<>(excluded) : new ArrayList<>();
        this.stateCount = stateCount;
    }

    public Map<AnalystTeam, List<MitigationTask>> getAssignments() {
        return Collections.unmodifiableMap(assignments);
    }

    public int getTotalValue() {
        return totalValue;
    }

    public List<MitigationTask> getExcluded() {
        return Collections.unmodifiableList(excluded);
    }

    public long getStateCount() {
        return stateCount;
    }

    @Override
    public String toString() {
        return "AssignmentResult{" +
                "assignmentsCount=" + assignments.size() +
                ", totalValue=" + totalValue +
                ", excludedCount=" + excluded.size() +
                ", stateCount=" + stateCount +
                '}';
    }
}
