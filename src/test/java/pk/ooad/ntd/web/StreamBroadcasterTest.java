package pk.ooad.ntd.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Severity;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StreamBroadcasterTest {

    @Test
    @DisplayName("StreamBroadcaster: onAlert stores recent alerts, clearRecentAlerts empties feed")
    void testClearRecentAlerts() {
        StreamBroadcaster broadcaster = new StreamBroadcaster();
        assertEquals(0, broadcaster.getAlertCount());
        assertTrue(broadcaster.getRecentAlerts(10).isEmpty());

        pk.ooad.ntd.domain.LowAlert alert1 = new pk.ooad.ntd.domain.LowAlert("a1", Instant.now(), AttackType.PORT_SCAN,
                "10.0.0.1", "10.0.0.2", "PortScanDetector", "Scan detected");
        pk.ooad.ntd.domain.CriticalAlert alert2 = new pk.ooad.ntd.domain.CriticalAlert("a2", Instant.now(), AttackType.DOS_FLOOD,
                "10.0.0.3", "10.0.0.4", "DosFloodDetector", "Flood detected");

        broadcaster.onAlert(alert1);
        broadcaster.onAlert(alert2);

        assertEquals(2, broadcaster.getAlertCount());
        assertEquals(2, broadcaster.getRecentAlerts(10).size());

        broadcaster.clearRecentAlerts();
        assertEquals(0, broadcaster.getAlertCount());
        assertTrue(broadcaster.getRecentAlerts(10).isEmpty());

        broadcaster.close();
    }
}
