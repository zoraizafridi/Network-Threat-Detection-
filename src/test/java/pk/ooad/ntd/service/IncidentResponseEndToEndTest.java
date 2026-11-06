package pk.ooad.ntd.service;

import org.junit.jupiter.api.Test;
import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.ResponsePlan;
import pk.ooad.ntd.domain.TopologyLoader;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IncidentResponseEndToEndTest {
    @Test
    void seededPortScanFlowsThroughDetectionRiskResponseAndReporting() throws InterruptedException {
        Network network = TopologyLoader.loadSample();
        IncidentResponseFacade facade = new IncidentResponseFacade(network, 424242L);
        CountDownLatch alertReceived = new CountDownLatch(1);
        AtomicReference<pk.ooad.ntd.domain.Alert> observedAlert = new AtomicReference<>();
        AlertListener listener = alert -> {
            observedAlert.set(alert);
            alertReceived.countDown();
        };
        facade.addAlertListener(listener);
        try {
            facade.start();
            facade.launchAttack(AttackType.PORT_SCAN, "198.51.100.44", "10.0.1.10");
            assertTrue(alertReceived.await(3, TimeUnit.SECONDS), "The detection engine should publish the injected scan alert");
            assertNotNull(observedAlert.get());
            assertTrue(network.findByIp("10.0.1.10").getRiskScore() > 0.0);

            ResponsePlan response = facade.runResponse();
            assertNotNull(response);
            assertTrue(response.getBackbone().isConnected());
            String report = facade.generateReport();
            assertTrue(report.contains("Incident{"));
            assertTrue(report.contains("198.51.100.44"));
        } finally {
            facade.stop();
        }
    }
}
