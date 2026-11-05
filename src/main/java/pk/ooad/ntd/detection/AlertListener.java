package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;

public interface AlertListener {
    void onAlert(Alert a);
}

