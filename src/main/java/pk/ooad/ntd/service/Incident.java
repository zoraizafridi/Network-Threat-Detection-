package pk.ooad.ntd.service;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.IncidentStatus;
import pk.ooad.ntd.domain.Severity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class Incident {
    private final String id;
    private final String sourceIp;
    private final Instant openedAt;
    private IncidentStatus status;
    private final List<Alert> alerts = new ArrayList<>();

    public Incident(String id, Alert firstAlert) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(firstAlert, "firstAlert must not be null");
        sourceIp = firstAlert.getSourceIp();
        openedAt = firstAlert.getTimestamp();
        status = IncidentStatus.OPEN;
        addAlert(firstAlert);
    }

    public Incident(String id, String sourceIp, Instant openedAt, IncidentStatus status, List<Alert> restored) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.sourceIp = sourceIp == null ? "" : sourceIp;
        this.openedAt = openedAt;
        this.status = status == null ? IncidentStatus.OPEN : status;
        if (restored != null) {
            for (Alert alert : restored) {
                addAlert(alert);
            }
        }
    }

    public void addAlert(Alert alert) {
        Objects.requireNonNull(alert, "alert must not be null");
        if (!alerts.contains(alert)) alerts.add(alert);
    }

    public List<String> alertIds() {
        return alerts.stream().map(Alert::getId).toList();
    }

    public Severity getHighestSeverity() {
        return alerts.stream().map(Alert::getSeverity)
                .max(Severity::compareTo).orElse(null);
    }

    public void close() {
        status = IncidentStatus.CLOSED;
    }

    public String getId() {
        return id;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public IncidentStatus getStatus() {
        return status;
    }

    public Instant getOpenedAt() {
        return openedAt;
    }

    public List<Alert> getAlerts() {
        return Collections.unmodifiableList(new ArrayList<>(alerts));
    }

    String sourceIpValue() {
        return sourceIp;
    }

    Instant openedAtValue() {
        return openedAt;
    }

    IncidentStatus statusValue() {
        return status;
    }

    @Override
    public String toString() {
        return "Incident{" + "id='" + id + '\'' + ", sourceIp='" + sourceIp + '\''
                + ", openedAt=" + openedAt + ", status=" + status + ", alertCount=" + alerts.size()
                + ", highestSeverity=" + getHighestSeverity() + '}';
    }
}
