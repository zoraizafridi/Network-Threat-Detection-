package pk.ooad.ntd.simulation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import pk.ooad.ntd.util.ConfigManager;

public class HostProfile {
    private double meanBytes;
    private double stdBytes;
    private List<Integer> commonPorts;
    private double eventsPerSecond;

    public HostProfile(double meanBytes, double stdBytes, List<Integer> commonPorts, double eventsPerSecond) {
        this.meanBytes = meanBytes;
        this.stdBytes = stdBytes;
        this.commonPorts = commonPorts != null ? new ArrayList<>(commonPorts) : new ArrayList<>();
        this.eventsPerSecond = eventsPerSecond;
    }

    public HostProfile() {
        this(
                ConfigManager.getInstance().getDouble("sim.host.meanBytes", 512.0),
                ConfigManager.getInstance().getDouble("sim.host.stdBytes", 64.0),
                List.of(80, 443, 22),
                ConfigManager.getInstance().getDouble("sim.host.eventsPerSecond", 5.0));
    }

    public double getMeanBytes() {
        return meanBytes;
    }

    public void setMeanBytes(double meanBytes) {
        this.meanBytes = meanBytes;
    }

    public double getStdBytes() {
        return stdBytes;
    }

    public void setStdBytes(double stdBytes) {
        this.stdBytes = stdBytes;
    }

    public List<Integer> getCommonPorts() {
        return Collections.unmodifiableList(commonPorts);
    }

    public void setCommonPorts(List<Integer> commonPorts) {
        this.commonPorts = commonPorts != null ? new ArrayList<>(commonPorts) : new ArrayList<>();
    }

    public double getEventsPerSecond() {
        return eventsPerSecond;
    }

    public void setEventsPerSecond(double eventsPerSecond) {
        this.eventsPerSecond = eventsPerSecond;
    }
}

