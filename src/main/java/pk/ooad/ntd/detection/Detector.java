package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.NetworkEvent;

import java.util.Objects;
import java.util.Optional;

public abstract class Detector {
    protected String name;
    protected final AlertFactory alertFactory = new AlertFactory();

    protected Detector(String name) {
        this.name = Objects.requireNonNull(name, "name must not be null");
    }

    public String getName() {
        return name;
    }

    public abstract Optional<Alert> analyze(NetworkEvent e);

    public abstract void reset();
}

