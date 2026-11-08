package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class AlertBus {
    private final List<AlertListener> listeners = new CopyOnWriteArrayList<>();
    private final List<AlertUpdateListener> updateListeners = new CopyOnWriteArrayList<>();

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

    public void subscribeUpdate(AlertUpdateListener l) {
        if (l != null && !updateListeners.contains(l)) {
            updateListeners.add(l);
        }
    }

    public void unsubscribeUpdate(AlertUpdateListener l) {
        if (l != null) {
            updateListeners.remove(l);
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
            }
        }
    }

    public void publishUpdate(Alert a) {
        if (a == null) {
            return;
        }
        for (AlertUpdateListener listener : updateListeners) {
            try {
                listener.onAlertUpdate(a);
            } catch (Exception e) {
            }
        }
    }

    public List<AlertListener> getListeners() {
        return Collections.unmodifiableList(listeners);
    }

    public List<AlertUpdateListener> getUpdateListeners() {
        return Collections.unmodifiableList(updateListeners);
    }
}
