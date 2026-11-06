package pk.ooad.ntd.ui;

import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AlertFactory;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.service.IncidentResponseFacade;

import javax.swing.JLabel;
import java.awt.Component;
import java.awt.Container;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertFeedPanelTest {
    @Test
    void alertModelStartsEmptyAndAddsNewestAlertFirst() {
        MutableClock clock = new MutableClock(Instant.parse("2026-11-06T10:00:00Z"));
        AlertTableModel model = new AlertTableModel(20, 10, clock);
        assertEquals(0, model.getRowCount());

        Alert older = alert("old", Severity.LOW);
        model.addAlert(older);
        clock.advanceSeconds(1);
        Alert newest = alert("new", Severity.CRITICAL);
        model.addAlert(newest);

        assertEquals(2, model.getRowCount());
        assertEquals("new", model.getValueAt(0, 3));
        assertEquals(Severity.CRITICAL, model.getValueAt(0, 1));
        assertEquals("old", model.getValueAt(1, 3));
    }

    @Test
    void alertModelDropsOldestRowsAtConfiguredMaximum() {
        MutableClock clock = new MutableClock(Instant.parse("2026-11-06T10:00:00Z"));
        AlertTableModel model = new AlertTableModel(2, 10, clock);
        model.addAlert(alert("one", Severity.LOW));
        clock.advanceSeconds(1);
        model.addAlert(alert("two", Severity.HIGH));
        clock.advanceSeconds(1);
        model.addAlert(alert("three", Severity.CRITICAL));

        assertEquals(2, model.getRowCount());
        assertEquals("three", model.getValueAt(0, 3));
        assertEquals("two", model.getValueAt(1, 3));
    }

    @Test
    void alertModelSummarizesPerSecondOverflowAndResumesNextSecond() {
        MutableClock clock = new MutableClock(Instant.parse("2026-11-06T10:00:00Z"));
        AlertTableModel model = new AlertTableModel(200, 10, clock);
        for (int index = 0; index < 15; index++) {
            model.addAlert(alert("source-" + index, Severity.HIGH));
        }
        assertEquals(11, model.getRowCount());
        assertEquals("+5 similar alerts", model.getValueAt(10, 0));

        clock.advanceSeconds(1);
        model.addAlert(alert("next-second", Severity.LOW));
        assertEquals(11, model.getRowCount());
        assertEquals("next-second", model.getValueAt(0, 3));
        for (int row = 0; row < model.getRowCount(); row++) {
            assertTrue(!"+5 similar alerts".equals(model.getValueAt(row, 0)));
        }
    }

    @Test
    void severityFilterHidesRowsOutsideSelectedSeverity() {
        MutableClock clock = new MutableClock(Instant.parse("2026-11-06T10:00:00Z"));
        AlertTableModel model = new AlertTableModel(20, 10, clock);
        model.addAlert(alert("low-source", Severity.LOW));
        model.addAlert(alert("high-source", Severity.HIGH));
        model.setSeverityFilter(Severity.HIGH);

        assertEquals(1, model.getRowCount());
        assertEquals("high-source", model.getValueAt(0, 3));
        assertEquals(Severity.HIGH, model.getValueAt(0, 1));
    }

    @Test
    void emptyPanelShowsConfiguredEmptyMessage() {
        AlertFeedPanel panel = new AlertFeedPanel(new IncidentResponseFacade(new Network(), 77L),
                new MutableClock(Instant.parse("2026-11-06T10:00:00Z")), 20, 10);
        assertEquals(0, panel.tableModel().getRowCount());
        JLabel emptyMessage = findLabel(panel, "alerts.empty.message");
        assertNotNull(emptyMessage);
        assertEquals("No alerts. Start the traffic.", emptyMessage.getText());
    }

    private Alert alert(String source, Severity severity) {
        return new AlertFactory().create(severity, AttackType.PORT_SCAN, source, "10.0.0.1",
                "PortScanDetector", "test", Instant.parse("2026-11-06T10:00:00Z"));
    }

    private JLabel findLabel(Component component, String name) {
        if (component instanceof JLabel label && name.equals(label.getName())) return label;
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                JLabel match = findLabel(child, name);
                if (match != null) return match;
            }
        }
        return null;
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        private void advanceSeconds(long seconds) {
            instant = instant.plusSeconds(seconds);
        }
    }
}
