package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;

@FunctionalInterface
public interface AlertUpdateListener {

    void onAlertUpdate(Alert alert);
}
