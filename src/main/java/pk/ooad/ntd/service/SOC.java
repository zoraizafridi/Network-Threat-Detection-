package pk.ooad.ntd.service;

import pk.ooad.ntd.detection.DetectionEngine;
import pk.ooad.ntd.domain.AnalystTeam;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class SOC {
    private final DetectionEngine detectionEngine;
    private final List<AnalystTeam> teams = new ArrayList<>();

    public SOC(DetectionEngine detectionEngine) {
        this.detectionEngine = Objects.requireNonNull(detectionEngine, "detectionEngine must not be null");
    }

    public void addTeam(AnalystTeam team) {
        if (team != null && !teams.contains(team)) teams.add(team);
    }

    public List<AnalystTeam> getAvailableTeams() {
        return teams.stream().filter(AnalystTeam::isAvailable).toList();
    }
}
