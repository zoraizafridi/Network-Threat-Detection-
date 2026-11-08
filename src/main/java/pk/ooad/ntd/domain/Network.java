package pk.ooad.ntd.domain;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;

public class Network {
    private final Map<String, NetworkAsset> assets = new LinkedHashMap<>();
    private final List<Link> links = new ArrayList<>();

    public void addAsset(NetworkAsset asset) {
        Objects.requireNonNull(asset, "Asset must not be null");
        if (assets.containsKey(asset.getId())) {
            throw new IllegalArgumentException("Asset with id " + asset.getId() + " already exists in network");
        }
        assets.put(asset.getId(), asset);
    }

    public boolean removeAsset(String id) {
        if (id == null) {
            return false;
        }
        NetworkAsset removed = assets.remove(id);
        if (removed != null) {
            links.removeIf(link -> link.connects(removed));
            return true;
        }
        return false;
    }

    public void addLink(Link link) {
        Objects.requireNonNull(link, "Link must not be null");
        if (!assets.containsKey(link.getSource().getId()) || !assets.containsKey(link.getTarget().getId())) {
            throw new IllegalArgumentException("Both endpoints of link " + link.getId() + " must exist in the network");
        }
        for (Link existing : links) {
            if (existing.getId().equals(link.getId())) {
                throw new IllegalArgumentException("Link with id " + link.getId() + " already exists in network");
            }
        }
        links.add(link);
    }

    public NetworkAsset getAsset(String id) {
        if (id == null) {
            return null;
        }
        return assets.get(id);
    }

    public NetworkAsset findByIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return null;
        }
        for (NetworkAsset asset : assets.values()) {
            if (ip.equals(asset.getIp())) {
                return asset;
            }
        }
        return null;
    }

    public List<NetworkAsset> getNeighbours(NetworkAsset a) {
        if (a == null) {
            throw new IllegalArgumentException("Asset must not be null");
        }
        Set<NetworkAsset> neighbours = new LinkedHashSet<>();
        for (Link link : links) {
            if (link.connects(a)) {
                neighbours.add(link.getOtherEnd(a));
            }
        }
        return new ArrayList<>(neighbours);
    }

    public List<Link> getLinksOf(NetworkAsset a) {
        if (a == null) {
            throw new IllegalArgumentException("Asset must not be null");
        }
        List<Link> result = new ArrayList<>();
        for (Link link : links) {
            if (link.connects(a)) {
                result.add(link);
            }
        }
        return result;
    }

    public List<Link> getCompromisedLinks() {
        List<Link> compromised = new ArrayList<>();
        for (Link link : links) {
            if (link.getStatus() == LinkStatus.COMPROMISED) {
                compromised.add(link);
            }
        }
        return compromised;
    }

    public boolean isConnected() {
        if (assets.size() <= 1) {
            return true;
        }
        NetworkAsset start = assets.values().iterator().next();
        Set<NetworkAsset> visited = new HashSet<>();
        Queue<NetworkAsset> queue = new ArrayDeque<>();

        visited.add(start);
        queue.add(start);

        while (!queue.isEmpty()) {
            NetworkAsset current = queue.poll();
            for (NetworkAsset neighbour : getNeighbours(current)) {
                if (visited.add(neighbour)) {
                    queue.add(neighbour);
                }
            }
        }

        return visited.size() == assets.size();
    }

    public void resetAll() {
        for (NetworkAsset asset : assets.values()) {
            asset.resetRisk();
            asset.setStatus(AssetStatus.NORMAL);
        }
        for (Link link : links) {
            link.reset();
        }
    }

    public Collection<NetworkAsset> getAssets() {
        return Collections.unmodifiableCollection(assets.values());
    }

    public List<Link> getLinks() {
        return Collections.unmodifiableList(links);
    }
}
