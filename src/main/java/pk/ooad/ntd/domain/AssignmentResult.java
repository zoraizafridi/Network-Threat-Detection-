package pk.ooad.ntd.domain;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class AssignmentResult {
    private final Map<AnalystTeam, List<MitigationTask>> assignments;
    private final int totalValue;
    private final int[][] dpTable;

    public AssignmentResult(Map<AnalystTeam, List<MitigationTask>> assignments, int totalValue, int[][] dpTable) {
        this.assignments = assignments != null ? new LinkedHashMap<>(assignments) : new LinkedHashMap<>();
        this.totalValue = totalValue;
        this.dpTable = dpTable != null ? dpTable : new int[0][0];
    }

    public Map<AnalystTeam, List<MitigationTask>> getAssignments() {
        return Collections.unmodifiableMap(assignments);
    }

    public int getTotalValue() {
        return totalValue;
    }

    public int[][] getDpTable() {
        return dpTable;
    }

    @Override
    public String toString() {
        return "AssignmentResult{" +
                "assignmentsCount=" + assignments.size() +
                ", totalValue=" + totalValue +
                '}';
    }
}

