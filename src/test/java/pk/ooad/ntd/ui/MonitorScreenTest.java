package pk.ooad.ntd.ui;

import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.Server;
import pk.ooad.ntd.service.IncidentResponseFacade;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.MatteBorder;
import java.awt.Component;
import java.awt.Container;
import java.awt.Color;
import java.awt.Point;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MonitorScreenTest {
    @Test
    void monitorMetricsAndPanelsUseEqualColumnsAndAlignedOuterMargins() throws Exception {
        IncidentResponseFacade facade = new IncidentResponseFacade(new Network(), 411L);
        AtomicReference<MainFrame> frameReference = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            MainFrame frame = new MainFrame(facade);
            frame.setSize(1366, 768);
            frame.setVisible(true);
            frameReference.set(frame);
        });
        MainFrame frame = frameReference.get();
        try {
            SwingUtilities.invokeAndWait(() -> {
                Container monitor = (Container) findComponent(frame, "monitor.screen");
                Container strip = (Container) findComponent(frame, "monitor.metric-strip");
                Container body = (Container) findComponent(frame, "monitor.body");
                Component map = findComponent(frame, "monitor.network-map");
                Component rightColumn = findComponent(frame, "monitor.right-column");
                Component host = findComponent(frame, "monitor.host-panel");
                assertNotNull(monitor);
                assertNotNull(strip);
                assertNotNull(body);
                assertNotNull(map);
                assertNotNull(rightColumn);
                assertNotNull(host);

                int minWidth = Integer.MAX_VALUE;
                int maxWidth = Integer.MIN_VALUE;
                for (int index = 0; index < 4; index++) {
                    JPanel column = (JPanel) findComponent(frame, "monitor.metric.column." + index);
                    assertNotNull(column);
                    minWidth = Math.min(minWidth, column.getWidth());
                    maxWidth = Math.max(maxWidth, column.getWidth());
                    if (index < 3) {
                        assertTrue(column.getBorder() instanceof CompoundBorder);
                        CompoundBorder border = (CompoundBorder) column.getBorder();
                        assertTrue(border.getOutsideBorder() instanceof MatteBorder);
                        MatteBorder rule = (MatteBorder) border.getOutsideBorder();
                        assertEquals(1, rule.getBorderInsets().right);
                        assertEquals(new Color(0xC9BA9A), rule.getMatteColor());
                    }
                }
                assertTrue(maxWidth - minWidth <= 1, "Metric columns should have equal widths");

                assertEquals(strip.getWidth(), body.getWidth());
                Point stripPoint = SwingUtilities.convertPoint(strip, 0, 0, monitor);
                Point mapPoint = SwingUtilities.convertPoint(map, 0, 0, monitor);
                assertEquals(24, stripPoint.x, "strip position=" + stripPoint + ", strip bounds="
                    + strip.getBounds() + ", monitor bounds=" + monitor.getBounds());
                assertTrue(mapPoint.x == 24, "map position=" + mapPoint + ", map bounds=" + map.getBounds()
                    + ", parent=" + map.getParent().getBounds() + ", body=" + body.getBounds()
                    + ", monitor=" + monitor.getBounds());
                Point hostPoint = SwingUtilities.convertPoint(host, 0, 0, body);
                Point rightPoint = SwingUtilities.convertPoint(rightColumn, 0, 0, body);
                Point feedPoint = SwingUtilities.convertPoint(frame.monitorAlertFeed(), 0, 0, body);
                assertEquals(24, map.getY());
                assertEquals(32, rightPoint.x - map.getX() - map.getWidth());
                assertTrue(hostPoint.y > feedPoint.y);
                assertTrue(feedPoint.y + frame.monitorAlertFeed().getHeight() <= hostPoint.y);
                double mapShare = (double) map.getWidth() / (map.getWidth() + rightColumn.getWidth());
                assertTrue(mapShare > 0.60 && mapShare < 0.70,
                    "Map should use about two thirds of panel width, actual share " + mapShare
                        + " (map " + map.getWidth() + ", host " + host.getWidth() + ")");
                assertTrue(!((HostPanel) host).isOpaque(), "Host panel should have no filled background box");
            });
        } finally {
            SwingUtilities.invokeAndWait(frame::dispose);
        }
    }

    @Test
    void metricsStartAtZeroAndAlertCountUpdatesOnEdtAfterFacadePublishes() throws Exception {
        IncidentResponseFacade facade = new IncidentResponseFacade(new Network(), 212L);
        AtomicReference<MainFrame> frameReference = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            MainFrame frame = new MainFrame(facade);
            frame.setVisible(true);
            frameReference.set(frame);
        });
        MainFrame frame = frameReference.get();
        CountDownLatch alertDelivered = new CountDownLatch(1);
        facade.addAlertListener(alert -> alertDelivered.countDown());
        try {
            assertEquals("0", findLabel(frame, "monitor.metric.1.value").getText());
            facade.start();
            facade.launchAttack(AttackType.PORT_SCAN, "198.51.100.4", "10.0.1.10");
            assertTrue(alertDelivered.await(3, TimeUnit.SECONDS), "The facade should publish the injected attack alert");
            SwingUtilities.invokeAndWait(() -> { });
            assertEquals("1", findLabel(frame, "monitor.metric.1.value").getText());
        } finally {
            facade.stop();
            SwingUtilities.invokeAndWait(frame::dispose);
        }
    }

    @Test
    void disposedMainFrameIgnoresLaterFacadeAlerts() throws Exception {
        IncidentResponseFacade facade = new IncidentResponseFacade(new Network(), 313L);
        AtomicReference<MainFrame> frameReference = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            MainFrame frame = new MainFrame(facade);
            frame.setVisible(true);
            frameReference.set(frame);
        });
        MainFrame frame = frameReference.get();
        assertEquals("0", findLabel(frame, "monitor.metric.1.value").getText());
        SwingUtilities.invokeAndWait(frame::dispose);

        CountDownLatch alertDelivered = new CountDownLatch(1);
        facade.addAlertListener(alert -> alertDelivered.countDown());
        try {
            facade.start();
            facade.launchAttack(AttackType.PORT_SCAN, "198.51.100.4", "10.0.1.10");
            assertTrue(alertDelivered.await(3, TimeUnit.SECONDS), "The facade should publish an alert after disposal");
            SwingUtilities.invokeAndWait(() -> { });
            assertEquals("0", findLabel(frame, "monitor.metric.1.value").getText());
        } finally {
            facade.stop();
        }
    }

    @Test
    void mainFrameUsesSeparateMonitorAndAlertsFeedPanels() {
        MainFrame frame = new MainFrame(new IncidentResponseFacade(new Network(), 414L));
        try {
            assertNotNull(frame.monitorAlertFeed());
            assertNotNull(frame.alertsScreenFeed());
            assertTrue(frame.monitorAlertFeed() != frame.alertsScreenFeed());
        } finally {
            frame.dispose();
        }
    }

    @Test
    void hostPanelShowsTheDefinitionRowsAndNoSelectionMessage() throws Exception {
        HostPanel panel = new HostPanel();
        NetworkAsset host = new Server("srv-1", "Web server", "10.2.0.4", 3);
        host.addRisk(72);
        SwingUtilities.invokeAndWait(() -> panel.showHost(host));

        assertEquals("Web server", findLabel(panel, "host.row.name.value").getText());
        assertEquals("10.2.0.4", findLabel(panel, "host.row.ip.value").getText());
        assertEquals("SERVER", findLabel(panel, "host.row.type.value").getText());
        assertEquals("72 of 100", findLabel(panel, "host.row.risk.value").getText());
        assertEquals("NORMAL", findLabel(panel, "host.row.status.value").getText());
        assertEquals("None", findLabel(panel, "host.row.last-alert.value").getText());

        SwingUtilities.invokeAndWait(() -> panel.showHost(null));
        JLabel emptyMessage = findLabel(panel, "host.empty.message");
        assertEquals("No host selected", emptyMessage.getText());
        assertNotNull(emptyMessage.getForeground());
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

    private Component findComponent(Component component, String name) {
        if (name.equals(component.getName())) return component;
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                Component match = findComponent(child, name);
                if (match != null) return match;
            }
        }
        return null;
    }
}
