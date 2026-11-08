package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;

/**
 * Final say on whether a detected alert reaches the bus.
 *
 * <p>It sits after detection and before publication, so a gate can drop noise
 * without teaching every detector about suppression. The default gate lets
 * everything through, which keeps the pipeline's behaviour unchanged until a
 * gate is installed.</p>
 */
public interface AlertGate {

    AlertGate ALLOW_ALL = alert -> true;

    boolean allow(Alert alert);
}
