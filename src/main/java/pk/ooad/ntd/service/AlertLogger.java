package pk.ooad.ntd.service;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

public class AlertLogger implements AlertListener {
    @Override
    public void onAlert(Alert alert) {
        if (alert == null) return;
        LogLevel level = switch (alert.getSeverity()) {
            case LOW -> LogLevel.INFO;
            case HIGH -> LogLevel.WARN;
            case CRITICAL -> LogLevel.ERROR;
        };
        EventLog.getInstance().log(level, alert.getDetectorName(), alert.toString());
    }
}
