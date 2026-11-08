package pk.ooad.ntd.ml;

import pk.ooad.ntd.flows.FlowRecord;

public final class FeatureVector {

    private FeatureVector() {
    }

    public static FlowFeatures of(FlowRecord flow) {
        if (flow == null) {
            throw new IllegalArgumentException("flow must not be null");
        }
        return new FlowFeatures(new double[] {
                Math.log1p(Math.max(0L, flow.bytesOut())),
                Math.log1p(Math.max(0L, flow.bytesIn())),
                Math.log1p(Math.max(0L, flow.packets())),
                flow.durationMs() / 1000.0,
                Math.log1p(Math.max(0, flow.srcPort())),
                flow.dstPort()
        });
    }
}
