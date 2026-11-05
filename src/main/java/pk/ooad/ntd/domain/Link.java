package pk.ooad.ntd.domain;

import java.util.Objects;

public class Link {
    private final String id;
    private final NetworkAsset source;
    private final NetworkAsset target;
    private final double baseCost;
    private final double bandwidth;
    private LinkStatus status;

    public Link(String id, NetworkAsset source, NetworkAsset target, double baseCost, double bandwidth) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.source = Objects.requireNonNull(source, "source asset must not be null");
        this.target = Objects.requireNonNull(target, "target asset must not be null");
        if (source.equals(target)) {
            throw new IllegalArgumentException("Link endpoints must be distinct assets: " + source.getId());
        }
        this.baseCost = baseCost;
        this.bandwidth = bandwidth;
        this.status = LinkStatus.NORMAL;
    }

    public NetworkAsset getOtherEnd(NetworkAsset a) {
        if (a == null) {
            throw new IllegalArgumentException("Asset must not be null");
        }
        if (a.equals(source)) {
            return target;
        }
        if (a.equals(target)) {
            return source;
        }
        throw new IllegalArgumentException("Asset " + a.getId() + " is not connected by link " + id);
    }

    public boolean connects(NetworkAsset a) {
        return a != null && (a.equals(source) || a.equals(target));
    }

    public void markCompromised() {
        this.status = LinkStatus.COMPROMISED;
    }

    public void reset() {
        this.status = LinkStatus.NORMAL;
    }

    public String getId() {
        return id;
    }

    public NetworkAsset getSource() {
        return source;
    }

    public NetworkAsset getTarget() {
        return target;
    }

    public double getBaseCost() {
        return baseCost;
    }

    public double getBandwidth() {
        return bandwidth;
    }

    public LinkStatus getStatus() {
        return status;
    }

    public void setStatus(LinkStatus status) {
        this.status = Objects.requireNonNull(status, "LinkStatus must not be null");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Link link = (Link) o;
        return Objects.equals(id, link.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "Link{" +
                "id='" + id + '\'' +
                ", source=" + source.getId() +
                ", target=" + target.getId() +
                ", baseCost=" + baseCost +
                ", bandwidth=" + bandwidth +
                ", status=" + status +
                '}';
    }
}

