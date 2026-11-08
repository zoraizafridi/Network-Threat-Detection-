package pk.ooad.ntd.ml;

/**
 * A fixed-position numeric view of a flow, built by {@link FeatureVector}.
 *
 * <p>The positions are fixed and documented so a model trained by one run can be
 * read by another: {@code [log bytes out, log bytes in, log packets, duration
 * seconds, log source port, destination port]}. The logarithms keep byte counts
 * from dominating a distance that also contains ports and seconds.</p>
 */
public record FlowFeatures(double[] values) {

    public static final int SIZE = 6;

    public FlowFeatures {
        if (values == null || values.length != SIZE) {
            throw new IllegalArgumentException("A flow feature vector must have " + SIZE + " values");
        }
        values = values.clone();
    }

    @Override
    public double[] values() {
        return values.clone();
    }

    public double value(int index) {
        return values[index];
    }
}
