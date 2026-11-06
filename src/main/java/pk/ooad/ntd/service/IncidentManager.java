package pk.ooad.ntd.service;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.IncidentStatus;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public class IncidentManager implements AlertListener {
    private final int correlationWindowSeconds;
    private final List<Incident> incidents = new ArrayList<>();

    public IncidentManager() {
        correlationWindowSeconds = ConfigManager.getInstance()
                .getInt("incident.correlationWindowSeconds", 300);
        if (correlationWindowSeconds < 0) {
            throw new IllegalArgumentException("Incident correlation window must not be negative");
        }
    }

    @Override
    public synchronized void onAlert(Alert alert) {
        Objects.requireNonNull(alert, "alert must not be null");
        Incident correlated = incidents.stream()
                .filter(incident -> incident.statusValue() == IncidentStatus.OPEN)
                .filter(incident -> incident.sourceIpValue().equals(alert.getSourceIp()))
                .filter(incident -> withinWindow(incident, alert))
                .findFirst().orElse(null);
        if (correlated == null) {
            incidents.add(new Incident(UUID.randomUUID().toString(), alert));
        } else {
            correlated.addAlert(alert);
        }
    }

    public synchronized List<Incident> getIncidents() {
        return Collections.unmodifiableList(new ArrayList<>(incidents));
    }

    public synchronized void reset() {
        incidents.clear();
    }

    private boolean withinWindow(Incident incident, Alert alert) {
        try {
            return Math.abs(Duration.between(incident.openedAtValue(), alert.getTimestamp()).getSeconds())
                    <= correlationWindowSeconds;
        } catch (ArithmeticException e) {
            return false;
        }
    }
}
