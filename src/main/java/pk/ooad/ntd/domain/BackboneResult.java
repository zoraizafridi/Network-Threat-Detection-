package pk.ooad.ntd.domain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BackboneResult {
    private final List<Link> chosenLinks;
    private final double totalWeight;
    private final boolean connected;
    private final List<NetworkAsset> unreachable;

    public BackboneResult(List<Link> chosenLinks, double totalWeight, boolean connected, List<NetworkAsset> unreachable) {
        this.chosenLinks = chosenLinks != null ? new ArrayList<>(chosenLinks) : new ArrayList<>();
        this.totalWeight = totalWeight;
        this.connected = connected;
        this.unreachable = unreachable != null ? new ArrayList<>(unreachable) : new ArrayList<>();
    }

    public List<Link> getChosenLinks() {
        return Collections.unmodifiableList(chosenLinks);
    }

    public double getTotalWeight() {
        return totalWeight;
    }

    public boolean isConnected() {
        return connected;
    }

    public List<NetworkAsset> getUnreachable() {
        return Collections.unmodifiableList(unreachable);
    }

    @Override
    public String toString() {
        return "BackboneResult{" +
                "chosenLinksCount=" + chosenLinks.size() +
                ", totalWeight=" + totalWeight +
                ", connected=" + connected +
                ", unreachableCount=" + unreachable.size() +
                '}';
    }
}

