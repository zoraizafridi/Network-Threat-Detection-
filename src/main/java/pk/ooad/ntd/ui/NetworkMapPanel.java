package pk.ooad.ntd.ui;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AssetStatus;
import pk.ooad.ntd.domain.AssetType;
import pk.ooad.ntd.domain.Link;
import pk.ooad.ntd.domain.LinkStatus;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.NetworkAsset;
import pk.ooad.ntd.service.IncidentResponseFacade;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.ConcurrentModificationException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NetworkMapPanel extends JPanel implements AlertListener {
    private static final Color FOREST = new Color(0x1F3D2B);
    private static final Color FOREST_LINE = new Color(0x3E6650);
    private static final Color SAND = new Color(0xE8DCC4);
    private static final Color MUTED_ON_FOREST = new Color(0xB9C4B3);
    private static final Color NORMAL = new Color(0x8FBF9F);
    private static final Color SUSPICIOUS = new Color(0xE0A63B);
    private static final Color COMPROMISED = new Color(0xE5604D);
    private static final int PANEL_MARGIN = 32;
    private static final int NODE_LABEL_OFFSET = 28;
    private static final int HIT_RADIUS = 18;

    private final Network network;
    private final HostPanel hostPanel;
    private List<NetworkAsset> layoutAssets = List.of();
    private Map<String, Point> nodePositions = Map.of();
    private int layoutWidth = -1;
    private int layoutHeight = -1;
    private NetworkAsset selectedAsset;

    public NetworkMapPanel(IncidentResponseFacade facade, HostPanel hostPanel) {
        network = facade.getNetwork();
        this.hostPanel = hostPanel;
        setOpaque(true);
        setBackground(FOREST);
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                selectAt(event.getX(), event.getY());
            }
        });
        facade.addAlertListener(this);
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);
        List<NetworkAsset> assets;
        List<Link> links;
        try {
            assets = new ArrayList<>(network.getAssets());
            links = new ArrayList<>(network.getLinks());
        } catch (ConcurrentModificationException exception) {
            return;
        }

        ensureLayout(getWidth(), getHeight(), assets);
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            for (Link link : links) drawLink(g, link);
            for (NetworkAsset asset : assets) drawNode(g, asset);
        } finally {
            g.dispose();
        }
    }

    @Override
    public void onAlert(Alert alert) {
        SwingUtilities.invokeLater(() -> {
            if (!isDisplayable()) return;
            repaint();
        });
    }

    private void ensureLayout(int width, int height, List<NetworkAsset> assets) {
        if (width == layoutWidth && height == layoutHeight) return;
        recomputeLayout(width, height, assets);
    }

    private void recomputeLayout(int width, int height, List<NetworkAsset> currentAssets) {
        List<NetworkAsset> assets = new ArrayList<>(currentAssets);
        assets.sort(Comparator.comparing(NetworkAsset::getId));
        Map<String, Point> positions = new HashMap<>();
        int count = assets.size();
        if (count > 0) {
            double centerX = width / 2.0;
            double centerY = height / 2.0 - 8.0;
            double radiusX = Math.max(0.0, width / 2.0 - PANEL_MARGIN - 16.0);
            double radiusY = Math.max(0.0, height / 2.0 - PANEL_MARGIN - NODE_LABEL_OFFSET);
            for (int index = 0; index < count; index++) {
                double angle = -Math.PI / 2.0 + (Math.PI * 2.0 * index) / count;
                int x = (int) Math.round(centerX + radiusX * Math.cos(angle));
                int y = (int) Math.round(centerY + radiusY * Math.sin(angle));
                positions.put(assets.get(index).getId(), new Point(x, y));
            }
        }
        layoutAssets = List.copyOf(assets);
        nodePositions = Map.copyOf(positions);
        layoutWidth = width;
        layoutHeight = height;
    }

    private void drawLink(Graphics2D g, Link link) {
        Point source = nodePositions.get(link.getSource().getId());
        Point target = nodePositions.get(link.getTarget().getId());
        if (source == null || target == null) return;
        boolean compromised = link.getStatus() == LinkStatus.COMPROMISED;
        g.setColor(compromised ? COMPROMISED : FOREST_LINE);
        g.setStroke(new BasicStroke(compromised ? 2f : 1f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g.drawLine(source.x, source.y, target.x, target.y);
    }

    private void drawNode(Graphics2D g, NetworkAsset asset) {
        Point center = nodePositions.get(asset.getId());
        if (center == null) return;
        g.setColor(statusColor(asset.getStatus()));
        g.setStroke(new BasicStroke(1.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        drawGlyph(g, asset.getType(), center);
        if (selectedAsset != null && selectedAsset.getId().equals(asset.getId())) {
            g.setColor(SAND);
            g.setStroke(new BasicStroke(1f));
            g.draw(new Ellipse2D.Double(center.x - 18, center.y - 18, 36, 36));
        }
        drawHostName(g, asset.getName(), center);
    }

    private void drawGlyph(Graphics2D g, AssetType type, Point center) {
        int x = center.x;
        int y = center.y;
        switch (type) {
            case SERVER -> {
                g.draw(new RoundRectangle2D.Double(x - 10, y - 10, 20, 20, 4, 4));
                g.drawLine(x - 6, y - 3, x + 6, y - 3);
                g.drawLine(x - 6, y + 4, x + 6, y + 4);
            }
            case WORKSTATION -> {
                g.drawRect(x - 10, y - 10, 20, 16);
                g.drawLine(x - 12, y + 10, x + 12, y + 10);
                g.drawLine(x, y + 6, x, y + 10);
            }
            case ROUTER -> {
                g.draw(new Ellipse2D.Double(x - 8, y - 8, 16, 16));
                g.drawLine(x, y - 14, x, y - 10);
                g.drawLine(x, y + 10, x, y + 14);
                g.drawLine(x - 14, y, x - 10, y);
                g.drawLine(x + 10, y, x + 14, y);
            }
            case IOT_DEVICE -> {
                Path2D diamond = new Path2D.Double();
                diamond.moveTo(x, y - 12);
                diamond.lineTo(x + 12, y);
                diamond.lineTo(x, y + 12);
                diamond.lineTo(x - 12, y);
                diamond.closePath();
                g.draw(diamond);
            }
        }
    }

    private void drawHostName(Graphics2D g, String name, Point center) {
        g.setColor(MUTED_ON_FOREST);
        g.setFont(new Font("IBM Plex Mono", Font.PLAIN, 12));
        FontMetrics metrics = g.getFontMetrics();
        int x = center.x - metrics.stringWidth(name) / 2;
        x = Math.max(PANEL_MARGIN, Math.min(x, getWidth() - PANEL_MARGIN - metrics.stringWidth(name)));
        g.drawString(name, x, center.y + NODE_LABEL_OFFSET);
    }

    private Color statusColor(AssetStatus status) {
        return switch (status) {
            case NORMAL -> NORMAL;
            case SUSPICIOUS -> SUSPICIOUS;
            case COMPROMISED -> COMPROMISED;
        };
    }

    private void selectAt(int x, int y) {
        if (getWidth() != layoutWidth || getHeight() != layoutHeight) {
            List<NetworkAsset> assets;
            try {
                assets = new ArrayList<>(network.getAssets());
            } catch (ConcurrentModificationException exception) {
                return;
            }
            ensureLayout(getWidth(), getHeight(), assets);
        }
        NetworkAsset match = null;
        for (NetworkAsset asset : layoutAssets) {
            Point center = nodePositions.get(asset.getId());
            if (center != null && center.distance(x, y) <= HIT_RADIUS) {
                match = asset;
                break;
            }
        }
        selectedAsset = match;
        hostPanel.showHost(match);
        repaint();
    }
}
