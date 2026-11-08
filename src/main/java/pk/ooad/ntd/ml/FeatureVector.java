package pk.ooad.ntd.ml;

import pk.ooad.ntd.flows.FlowRecord;

/**
 * Builds the numeric vector a model sees from one {@link FlowRecord}.
 *
 * <p>The conversion is kept in one place on purpose. Training and scoring must
 * agree on what position four means, and two copies of this arithmetic would
 * eventually disagree without anything failing loudly.</p>
 *
 * <p>Byte and packet counts are compressed with {@code log1p} so a megabyte
 * transfer does not dominate a distance that also contains ports and seconds.
 * Counters are clamped at zero because a projection of a feed should never
 * produce a negative magnitude.</p>
 */
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
