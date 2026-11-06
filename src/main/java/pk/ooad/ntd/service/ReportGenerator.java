package pk.ooad.ntd.service;

import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.ResponsePlan;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class ReportGenerator {
    public String generate(List<Incident> incidents, Network network, ResponsePlan plan) {
        StringBuilder report = new StringBuilder("Incident Response Report").append(System.lineSeparator());
        report.append("Incidents: ").append(incidents == null ? 0 : incidents.size()).append(System.lineSeparator());
        if (incidents != null) {
            for (Incident incident : incidents) report.append(incident).append(System.lineSeparator());
        }
        if (network != null) {
            report.append("Network assets: ").append(network.getAssets().size())
                    .append(", links: ").append(network.getLinks().size()).append(System.lineSeparator());
        }
        if (plan != null) {
            report.append("Backbone connected: ").append(plan.getBackbone().isConnected())
                    .append(", total weight: ").append(plan.getBackbone().getTotalWeight())
                    .append(System.lineSeparator());
            report.append("Assigned mitigation value: ").append(plan.getAssignment().getTotalValue())
                    .append(System.lineSeparator());
        }
        return report.toString();
    }

    public void export(String report, String path) {
        if (report == null) throw new IllegalArgumentException("report must not be null");
        if (path == null || path.isBlank()) throw new IllegalArgumentException("path must not be blank");
        try {
            Path output = Path.of(path);
            Path parent = output.getParent();
            if (parent != null) Files.createDirectories(parent);
            Files.writeString(output, report, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("Unable to export report to " + path, e);
        }
    }
}
