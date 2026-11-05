package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class AlertBus {
    private final List<AlertListener> listeners = new CopyOnWriteArrayList<>();

    public void subscribe(AlertListener l) {
        if (l != null && !listeners.contains(l)) {
            listeners.add(l);
        }
    }

    public void unsubscribe(AlertListener l) {
        if (l != null) {
            listeners.remove(l);
        }
    }

    public void publish(Alert a) {
        if (a == null) {
            return;
        }
        for (AlertListener listener : listeners) {
            try {
                listener.onAlert(a);
            } catch (Exception e) {
                // A failing AlertListener must not break the others
            }
        }
    }

    public List<AlertListener> getListeners() {
        return Collections.unmodifiableList(listeners);
    }
}

