package pk.ooad.ntd.domain;

import java.util.Objects;

public class ResponsePlan {
    private final BackboneResult backbone;
    private final AssignmentResult assignment;

    public ResponsePlan(BackboneResult backbone, AssignmentResult assignment) {
        this.backbone = Objects.requireNonNull(backbone, "BackboneResult must not be null");
        this.assignment = Objects.requireNonNull(assignment, "AssignmentResult must not be null");
    }

    public BackboneResult getBackbone() {
        return backbone;
    }

    public AssignmentResult getAssignment() {
        return assignment;
    }

    @Override
    public String toString() {
        return "ResponsePlan{" +
                "backbone=" + backbone +
                ", assignment=" + assignment +
                '}';
    }
}
