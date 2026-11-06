package pk.ooad.ntd.service;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AssetStatus;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.util.ConfigManager;

import java.util.Objects;

public class RiskScorer implements AlertListener {
    private final Network network;
    private final double cap;
    private final double compromiseThreshold;
    private final double decayPerTick;

    public RiskScorer(Network network) {
        this.network = Objects.requireNonNull(network, "network must not be null");
        ConfigManager config = ConfigManager.getInstance();
        cap = Math.min(100.0, config.getDouble("risk.cap", 100.0));
        compromiseThreshold = config.getDouble("risk.compromiseThreshold", 60.0);
        decayPerTick = config.getDouble("risk.decayPerTick", 1.0);
        if (cap < 0 || compromiseThreshold < 0 || compromiseThreshold > cap || decayPerTick < 0) {
            throw new IllegalArgumentException("Risk configuration must be non-negative and the threshold must not exceed the cap");
        }
    }

    @Override
    public synchronized void onAlert(Alert alert) {
        if (alert == null) return;
        NetworkAsset asset = network.findByIp(alert.getTargetIp());
        if (asset == null) return;
        double previousRisk = asset.getRiskScore();
        double nextRisk = Math.min(cap, previousRisk + alert.getRiskIncrement());
        asset.addRisk(nextRisk - previousRisk);
        if (nextRisk >= compromiseThreshold) {
            asset.setStatus(AssetStatus.COMPROMISED);
            if (previousRisk < compromiseThreshold) markAdjacentLinks(asset);
        } else if (nextRisk > 0) {
            asset.setStatus(AssetStatus.SUSPICIOUS);
        }
    }

    public synchronized void decay() {
        for (NetworkAsset asset : network.getAssets()) {
            asset.addRisk(-decayPerTick);
            if (asset.getRiskScore() == 0.0) {
                asset.setStatus(AssetStatus.NORMAL);
            } else if (asset.getRiskScore() < compromiseThreshold) {
                asset.setStatus(AssetStatus.SUSPICIOUS);
            }
        }
    }

    public synchronized void reset() {
        network.resetAll();
    }

    private void markAdjacentLinks(NetworkAsset asset) {
        for (Link link : network.getLinksOf(asset)) link.markCompromised();
    }
}
