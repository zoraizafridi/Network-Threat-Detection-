package pk.ooad.ntd.containment;

import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.response.BackbonePlanner;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.function.Supplier;

public final class ContainmentSafeguards {

    public record Counters(long allowlist, long rateLimit, long partition) {
    }

    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final Clock clock;
    private final Supplier<Network> network;
    private final List<String> allowlist;
    private final int maxPerMinute;
    private final boolean partitionCheck;
    private final Deque<Instant> recent = new ArrayDeque<>();
    private long allowlistRefusals;
    private long rateRefusals;
    private long partitionRefusals;

    public ContainmentSafeguards(Clock clock, ConfigManager config, Supplier<Network> network) {
        this(clock, config.getString("containment.allowlist", ""),
                config.getInt("containment.maxPerMinute", 12),
                Boolean.parseBoolean(config.getString("containment.partitionCheck", "true")),
                network);
    }

    ContainmentSafeguards(Clock clock, String allowlist, int maxPerMinute, boolean partitionCheck,
                          Supplier<Network> network) {
        this.clock = clock;
        this.network = network;
        this.allowlist = split(allowlist);
        this.maxPerMinute = maxPerMinute;
        this.partitionCheck = partitionCheck;
    }

    public String refusal(String ip) {
        String address = ip == null ? "" : ip.trim();
        if (address.isEmpty()) {
            return null;
        }
        if (allowlisted(address)) {
            synchronized (this) {
                allowlistRefusals++;
            }
            return "address is on the containment allowlist";
        }
        synchronized (this) {
            Instant now = clock.instant();
            while (!recent.isEmpty() && recent.peekFirst().isBefore(now.minus(WINDOW))) {
                recent.removeFirst();
            }
            if (maxPerMinute > 0 && recent.size() >= maxPerMinute) {
                rateRefusals++;
                return "rate limit of " + maxPerMinute + " per minute reached";
            }
            if (partitionCheck && partitions(address)) {
                partitionRefusals++;
                return "blocking " + address + " would split the network";
            }
            recent.addLast(now);
        }
        return null;
    }

    public synchronized Counters counters() {
        return new Counters(allowlistRefusals, rateRefusals, partitionRefusals);
    }

    public int maxPerMinute() {
        return maxPerMinute;
    }

    public boolean partitionCheck() {
        return partitionCheck;
    }

    public List<String> allowlist() {
        return allowlist;
    }

    private boolean allowlisted(String address) {
        for (String entry : allowlist) {
            if (entry.endsWith("*")) {
                if (address.startsWith(entry.substring(0, entry.length() - 1))) {
                    return true;
                }
            } else if (entry.equals(address)) {
                return true;
            }
        }
        return false;
    }

    private boolean partitions(String address) {
        Network current = network == null ? null : network.get();
        if (current == null) {
            return false;
        }
        try {
            NetworkAsset target = current.findByIp(address);
            if (target == null || !current.isConnected()) {
                return false;
            }
            Network reduced = new Network();
            for (NetworkAsset asset : current.getAssets()) {
                if (!asset.getId().equals(target.getId())) {
                    reduced.addAsset(asset);
                }
            }
            for (Link link : current.getLinks()) {
                if (reduced.getAsset(link.getSource().getId()) != null
                        && reduced.getAsset(link.getTarget().getId()) != null) {
                    reduced.addLink(link);
                }
            }
            return !new BackbonePlanner().plan(reduced).isConnected();
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private static List<String> split(String raw) {
        List<String> entries = new ArrayList<>();
        if (raw == null) {
            return entries;
        }
        for (String part : raw.split(",")) {
            String entry = part.trim();
            if (!entry.isEmpty()) {
                entries.add(entry);
            }
        }
        return List.copyOf(entries);
    }
}
