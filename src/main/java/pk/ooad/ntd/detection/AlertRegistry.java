package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.util.ConfigManager;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class AlertRegistry implements AlertListener, AlertUpdateListener {

    private final int max;
    private final Map<String, Alert> byId = new LinkedHashMap<>();

    public AlertRegistry() {
        this(ConfigManager.getInstance().getInt("alerts.buffer.max", 500));
    }

    public AlertRegistry(int max) {
        this.max = Math.max(1, max);
    }

    @Override
    public synchronized void onAlert(Alert alert) {
        if (alert == null) {
            return;
        }
        byId.remove(alert.getId());
        byId.put(alert.getId(), alert);
        while (byId.size() > max) {
            Iterator<String> oldest = byId.keySet().iterator();
            oldest.next();
            oldest.remove();
        }
    }

    @Override
    public void onAlertUpdate(Alert alert) {
    }

    public synchronized Optional<Alert> find(String id) {
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(id));
    }

    public synchronized List<Alert> recent(int limit) {
        List<Alert> all = new ArrayList<>(byId.values());
        int count = Math.min(Math.max(limit, 0), all.size());
        return List.copyOf(all.subList(all.size() - count, all.size()));
    }

    public synchronized int size() {
        return byId.size();
    }

    public synchronized void clear() {
        byId.clear();
    }
}
