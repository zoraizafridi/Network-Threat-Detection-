package pk.ooad.ntd.response;

import pk.ooad.ntd.domain.AssetType;
import pk.ooad.ntd.domain.BackboneResult;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.LinkStatus;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.util.ConfigManager;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class BackbonePlanner {
    public BackboneResult plan(Network network) {
        Objects.requireNonNull(network, "network must not be null");
        List<NetworkAsset> hosts = new ArrayList<>(network.getAssets());
        hosts.sort(Comparator.comparing(NetworkAsset::getName).thenComparing(NetworkAsset::getId));
        if (hosts.isEmpty()) return new BackboneResult(List.of(), 0.0, true, List.of());

        Map<NetworkAsset, Integer> indexes = new HashMap<>();
        for (int i = 0; i < hosts.size(); i++) indexes.put(hosts.get(i), i);
        List<Link> candidates = network.getLinks().stream()
                .filter(link -> link.getStatus() != LinkStatus.COMPROMISED)
                .sorted(Comparator.comparingDouble(this::edgeWeight)
                        .thenComparing(Comparator.comparingDouble(this::combinedRisk).reversed())
                        .thenComparing(Link::getId))
                .toList();

        UnionFind sets = new UnionFind(hosts.size());
        List<Link> chosenLinks = new ArrayList<>();
        double totalWeight = 0.0;
        for (Link link : candidates) {
            Integer source = indexes.get(link.getSource());
            Integer target = indexes.get(link.getTarget());
            if (source != null && target != null && sets.union(source, target)) {
                chosenLinks.add(link);
                totalWeight += edgeWeight(link);
            }
        }

        NetworkAsset socHost = getSocHost(network);
        List<NetworkAsset> unreachable = new ArrayList<>();
        if (socHost == null) {
            unreachable.addAll(hosts);
        } else {
            int socRoot = sets.find(indexes.get(socHost));
            for (NetworkAsset host : hosts) {
                if (sets.find(indexes.get(host)) != socRoot) unreachable.add(host);
            }
        }
        unreachable.sort(Comparator.comparing(NetworkAsset::getName).thenComparing(NetworkAsset::getId));
        return new BackboneResult(chosenLinks, totalWeight, unreachable.isEmpty(), unreachable);
    }

    private NetworkAsset getSocHost(Network network) {
        String configuredId = ConfigManager.getInstance().getString("soc.host.id", null);
        if (configuredId != null && !configuredId.isBlank()) {
            return network.getAsset(configuredId.trim());
        }
        return network.getAssets().stream()
                .filter(asset -> asset.getType() == AssetType.ROUTER)
                .findFirst()
                .orElse(null);
    }

    private double combinedRisk(Link link) {
        return link.getSource().getRiskScore() + link.getTarget().getRiskScore();
    }

    private double edgeWeight(Link link) {
        return link.getBaseCost();
    }
}
