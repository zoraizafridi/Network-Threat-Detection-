package pk.ooad.ntd.response;

import pk.ooad.ntd.domain.BackboneResult;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.LinkStatus;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;

public class BackbonePlanner {
    public BackboneResult plan(Network network) {
        Objects.requireNonNull(network, "network must not be null");
        List<NetworkAsset> assets = new ArrayList<>(network.getAssets());
        Map<NetworkAsset, Integer> indexes = new HashMap<>();
        for (int i = 0; i < assets.size(); i++) indexes.put(assets.get(i), i);

        List<Link> candidates = network.getLinks().stream()
                .filter(link -> link.getStatus() != LinkStatus.COMPROMISED)
                .sorted(Comparator.comparingDouble(this::edgeWeight).thenComparing(Link::getId))
                .toList();
        UnionFind sets = new UnionFind(assets.size());
        List<Link> chosen = new ArrayList<>();
        double totalWeight = 0.0;
        for (Link link : candidates) {
            int source = indexes.get(link.getSource());
            int target = indexes.get(link.getTarget());
            if (sets.union(source, target)) {
                chosen.add(link);
                totalWeight += edgeWeight(link);
            }
        }

        if (assets.size() <= 1) {
            return new BackboneResult(chosen, totalWeight, true, List.of());
        }
        int root = sets.find(0);
        List<NetworkAsset> unreachable = assets.stream()
                .filter(asset -> sets.find(indexes.get(asset)) != root)
                .toList();
        return new BackboneResult(chosen, totalWeight, unreachable.isEmpty(), unreachable);
    }

    private double edgeWeight(Link link) {
        return link.getBaseCost() + (link.getSource().getRiskScore() + link.getTarget().getRiskScore()) / 100.0;
    }
}
