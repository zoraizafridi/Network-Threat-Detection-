package pk.ooad.ntd.web;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.detection.AlertUpdateListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.util.ConfigManager;

import io.javalin.http.sse.SseClient;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiFunction;
import java.util.function.Function;

public class StreamBroadcaster implements AlertListener, AlertUpdateListener {
    private final int recentMax;
    private final long networkIntervalNanos;

    private final Set<SseClient> clients = ConcurrentHashMap.newKeySet();
    private final Deque<Alert> recent = new ArrayDeque<>();
    private final AtomicLong frames = new AtomicLong();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "ntd-stream-network");
        thread.setDaemon(true);
        return thread;
    });

    private Function<Alert, String> alertJson = alert -> "";
    private java.util.function.Supplier<String> networkJson = () -> "{}";
    private BiFunction<String, String, String> stateJson = (username, role) -> "{}";
    private java.util.function.Supplier<String> incidentJson = () -> "{}";
    private long lastNetworkAt;
    private boolean networkPending;

    public StreamBroadcaster() {
        ConfigManager config = ConfigManager.getInstance();
        this.recentMax = Math.max(1, config.getInt("alerts.buffer.max", 500));
        this.networkIntervalNanos = Math.max(1L, config.getInt("stream.network.intervalMillis", 250)) * 1_000_000L;
    }

    void setEncoders(Function<Alert, String> alertJson, java.util.function.Supplier<String> networkJson,
                     BiFunction<String, String, String> stateJson, java.util.function.Supplier<String> incidentJson) {
        this.alertJson = alertJson;
        this.networkJson = networkJson;
        this.stateJson = stateJson;
        this.incidentJson = incidentJson;
    }

    @Override
    public void onAlert(Alert a) {
        if (a == null) {
            return;
        }
        synchronized (recent) {
            recent.addLast(a);
            while (recent.size() > recentMax) {
                recent.removeFirst();
            }
        }
        emit("alert", alertJson.apply(a));
        requestNetwork();
    }

    @Override
    public void onAlertUpdate(Alert a) {
        if (a == null) {
            return;
        }
        emit("alert", alertJson.apply(a));
    }

    public void addClient(SseClient c) {
        if (c == null) {
            return;
        }
        clients.add(c);
        emitOne(c, "hello", "{\"alertCount\":" + getAlertCount() + "}");
    }

    public void removeClient(SseClient c) {
        if (c != null) {
            clients.remove(c);
        }
    }

    public List<Alert> getRecentAlerts(int limit) {
        synchronized (recent) {
            int count = Math.min(Math.max(limit, 0), recent.size());
            return new ArrayList<>(recent).subList(recent.size() - count, recent.size());
        }
    }

    public void clearRecentAlerts() {
        synchronized (recent) {
            recent.clear();
        }
    }

    public Alert findAlert(String id) {
        if (id == null || id.isBlank()) {
            return null;
        }
        synchronized (recent) {
            for (Alert alert : recent) {
                if (id.equals(alert.getId())) {
                    return alert;
                }
            }
            return null;
        }
    }

    public void seed(List<Alert> history) {
        if (history == null || history.isEmpty()) {
            return;
        }
        synchronized (recent) {
            for (Alert alert : history) {
                if (alert == null) {
                    continue;
                }
                recent.addLast(alert);
                while (recent.size() > recentMax) {
                    recent.removeFirst();
                }
            }
        }
    }

    public int getAlertCount() {
        synchronized (recent) {
            return recent.size();
        }
    }

    public int getClientCount() {
        return clients.size();
    }

    public long getEmittedFrames() {
        return frames.get();
    }

    public void broadcastState() {
        for (SseClient client : List.copyOf(clients)) {
            String username = client.ctx().sessionAttribute("username");
            String role = client.ctx().sessionAttribute("role");
            emitOne(client, "state", stateJson.apply(username, role));
        }
    }

    public void broadcastIncidents() {
        String json;
        try {
            json = incidentJson.get();
        } catch (RuntimeException ignored) {
            return;
        }
        emit("incidents", json);
    }

    void requestNetwork() {
        long delay;
        synchronized (this) {
            long now = System.nanoTime();
            long wait = lastNetworkAt + networkIntervalNanos - now;
            if (wait <= 0) {
                lastNetworkAt = now;
                delay = 0L;
            } else if (!networkPending) {
                networkPending = true;
                delay = wait;
            } else {
                return;
            }
        }
        if (delay == 0L) {
            sendNetwork();
            return;
        }
        try {
            scheduler.schedule(this::flushNetwork, delay, TimeUnit.NANOSECONDS);
        } catch (RejectedExecutionException ignored) {
            synchronized (this) {
                networkPending = false;
            }
        }
    }

    void close() {
        scheduler.shutdownNow();
    }

    private void flushNetwork() {
        synchronized (this) {
            networkPending = false;
            lastNetworkAt = System.nanoTime();
        }
        sendNetwork();
    }

    private void sendNetwork() {
        String json;
        try {
            json = networkJson.get();
        } catch (RuntimeException ignored) {
            return;
        }
        emit("network", json);
    }

    private void emit(String event, String data) {
        for (SseClient client : List.copyOf(clients)) {
            emitOne(client, event, data);
        }
    }

    private void emitOne(SseClient client, String event, String data) {
        if (client.terminated()) {
            removeClient(client);
            return;
        }
        try {
            client.sendEvent(event, data);
            frames.incrementAndGet();
        } catch (RuntimeException ignored) {
            removeClient(client);
        }
    }
}
