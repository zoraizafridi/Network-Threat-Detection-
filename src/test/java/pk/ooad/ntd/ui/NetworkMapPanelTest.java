package pk.ooad.ntd.ui;

import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.service.IncidentResponseFacade;

import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NetworkMapPanelTest {
    private static final Color FOREST = new Color(0x1F3D2B);

    @Test
    void sampleNetworkPaintsNodesWithStableInBoundsLayout() throws Exception {
        Network network = TopologyLoader.loadSample();
        HostPanel hostPanel = new HostPanel();
        NetworkMapPanel panel = new NetworkMapPanel(new IncidentResponseFacade(network, 91L), hostPanel);
        panel.setSize(900, 600);
        BufferedImage firstImage = paint(panel);
        Map<String, Point> firstPositions = nodePositions(panel);
        BufferedImage secondImage = paint(panel);
        Map<String, Point> secondPositions = nodePositions(panel);

        assertEquals(firstPositions, secondPositions);
        assertEquals(network.getAssets().size(), firstPositions.size());
        for (NetworkAsset asset : network.getAssets()) {
            Point center = firstPositions.get(asset.getId());
            assertNotNull(center);
            assertTrue(center.x >= 32 && center.x < panel.getWidth() - 32);
            assertTrue(center.y >= 32 && center.y < panel.getHeight() - 32);
            assertTrue(hasNonGroundPixel(firstImage, center), "Node should paint near " + asset.getId());
            assertTrue(hasNonGroundPixel(secondImage, center), "Node should repaint near " + asset.getId());
        }
    }

    @Test
    void nodeClickSelectsHostAndEmptyClickClearsSelection() throws Exception {
        Network network = TopologyLoader.loadSample();
        HostPanel hostPanel = new HostPanel();
        NetworkMapPanel panel = new NetworkMapPanel(new IncidentResponseFacade(network, 92L), hostPanel);
        panel.setSize(900, 600);
        paint(panel);
        List<NetworkAsset> layoutAssets = layoutAssets(panel);
        NetworkAsset expected = layoutAssets.get(0);
        Point position = nodePositions(panel).get(expected.getId());

        SwingUtilities.invokeAndWait(() -> panel.dispatchEvent(new MouseEvent(panel, MouseEvent.MOUSE_CLICKED,
                System.currentTimeMillis(), 0, position.x, position.y, 1, false)));
        JLabel selectedName = findLabel(hostPanel, "host.row.name.value");
        assertNotNull(selectedName);
        assertEquals(expected.getName(), selectedName.getText());
        assertEquals(expected, selectedAsset(panel));

        SwingUtilities.invokeAndWait(() -> panel.dispatchEvent(new MouseEvent(panel, MouseEvent.MOUSE_CLICKED,
                System.currentTimeMillis(), 0, 4, 4, 1, false)));
        JLabel emptyMessage = findLabel(hostPanel, "host.empty.message");
        assertEquals("No host selected", emptyMessage.getText());
        assertNull(selectedAsset(panel));
    }

    @Test
    void groupedLayoutKeepsLabelsAndGlyphsDisjointAndInside1366By768Panel() throws Exception {
        Network network = TopologyLoader.loadSample();
        NetworkMapPanel panel = new NetworkMapPanel(new IncidentResponseFacade(network, 94L), new HostPanel());
        panel.setSize(1366, 768);
        paint(panel);

        Map<String, Point> firstLayout = nodePositions(panel);
        Map<String, Rectangle> glyphs = nodeBounds(panel);
        Map<String, Rectangle> labels = labelBounds(panel);
        paint(panel);
        assertEquals(firstLayout, nodePositions(panel));
        assertEquals(network.getAssets().size(), labels.size());

        for (String id : labels.keySet()) {
            Rectangle label = labels.get(id);
            assertTrue(label.x >= 32 && label.y >= 32);
            assertTrue(label.x + label.width <= panel.getWidth() - 32);
            assertTrue(label.y + label.height <= panel.getHeight() - 32);
            for (Map.Entry<String, Rectangle> glyph : glyphs.entrySet()) {
                assertFalse(label.intersects(glyph.getValue()),
                        "Label for " + id + " overlaps glyph for " + glyph.getKey());
            }
            for (Map.Entry<String, Rectangle> otherLabel : labels.entrySet()) {
                if (!id.equals(otherLabel.getKey())) {
                    assertFalse(label.intersects(otherLabel.getValue()),
                            "Label rectangles overlap for " + id + " and " + otherLabel.getKey());
                }
            }
        }
        for (Point position : firstLayout.values()) {
            assertTrue(position.x - 15 >= 0 && position.x + 15 < panel.getWidth());
            assertTrue(position.y - 15 >= 0 && position.y + 15 < panel.getHeight());
        }
    }

    private BufferedImage paint(NetworkMapPanel panel) {
        BufferedImage image = new BufferedImage(panel.getWidth(), panel.getHeight(), BufferedImage.TYPE_INT_ARGB);
        var graphics = image.createGraphics();
        try {
            panel.paint(graphics);
        } finally {
            graphics.dispose();
        }
        return image;
    }

    private boolean hasNonGroundPixel(BufferedImage image, Point center) {
        for (int y = Math.max(0, center.y - 20); y <= Math.min(image.getHeight() - 1, center.y + 20); y++) {
            for (int x = Math.max(0, center.x - 20); x <= Math.min(image.getWidth() - 1, center.x + 20); x++) {
                if (image.getRGB(x, y) != FOREST.getRGB()) return true;
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Point> nodePositions(NetworkMapPanel panel) throws ReflectiveOperationException {
        Field field = NetworkMapPanel.class.getDeclaredField("nodePositions");
        field.setAccessible(true);
        return (Map<String, Point>) field.get(panel);
    }

    @SuppressWarnings("unchecked")
    private List<NetworkAsset> layoutAssets(NetworkMapPanel panel) throws ReflectiveOperationException {
        Field field = NetworkMapPanel.class.getDeclaredField("layoutAssets");
        field.setAccessible(true);
        return (List<NetworkAsset>) field.get(panel);
    }

    private NetworkAsset selectedAsset(NetworkMapPanel panel) throws ReflectiveOperationException {
        Field field = NetworkMapPanel.class.getDeclaredField("selectedAsset");
        field.setAccessible(true);
        return (NetworkAsset) field.get(panel);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Rectangle> nodeBounds(NetworkMapPanel panel) throws ReflectiveOperationException {
        Field field = NetworkMapPanel.class.getDeclaredField("nodeBounds");
        field.setAccessible(true);
        return (Map<String, Rectangle>) field.get(panel);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Rectangle> labelBounds(NetworkMapPanel panel) throws ReflectiveOperationException {
        Field field = NetworkMapPanel.class.getDeclaredField("labelBounds");
        field.setAccessible(true);
        return (Map<String, Rectangle>) field.get(panel);
    }

    private JLabel findLabel(java.awt.Component component, String name) {
        if (component instanceof JLabel label && name.equals(label.getName())) return label;
        if (component instanceof java.awt.Container container) {
            for (java.awt.Component child : container.getComponents()) {
                JLabel match = findLabel(child, name);
                if (match != null) return match;
            }
        }
        return null;
    }
}
