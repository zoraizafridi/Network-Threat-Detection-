package pk.ooad.ntd.ml;

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
