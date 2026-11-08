package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;

public interface AlertGate {

    enum Outcome {
        DELIVERED,
        FOLDED,
        SUPPRESSED
    }

    record Decision(Outcome outcome, Alert foldedInto, String reason) {

        public static Decision deliver() {
            return new Decision(Outcome.DELIVERED, null, "");
        }

        public static Decision fold(Alert existing) {
            return new Decision(Outcome.FOLDED, existing, "duplicate");
        }

        public static Decision suppress(String reason) {
            return new Decision(Outcome.SUPPRESSED, null, reason == null ? "" : reason);
        }

        public boolean isDelivered() {
            return outcome == Outcome.DELIVERED;
        }

        public boolean isFolded() {
            return outcome == Outcome.FOLDED;
        }
    }

    AlertGate ALLOW_ALL = alert -> true;

    boolean allow(Alert alert);

    default Decision decide(Alert alert) {
        return allow(alert) ? Decision.deliver() : Decision.suppress("gate");
    }
}
