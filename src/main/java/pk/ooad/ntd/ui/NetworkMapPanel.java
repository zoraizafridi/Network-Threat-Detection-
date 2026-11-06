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
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.ConcurrentModificationException;
import java.util.EnumMap;
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
    private static final int LABEL_GAP = 4;
    private static final int LABEL_PADDING = 4;
    private static final int SLOT_GAP = 8;
    private static final int GLYPH_HALF_SIZE = 15;

    private final Network network;
    private final HostPanel hostPanel;
    private List<NetworkAsset> layoutAssets = List.of();
    private Map<String, Point> nodePositions = Map.of();
    private Map<String, Rectangle> nodeBounds = Map.of();
    private Map<String, Rectangle> labelBounds = Map.of();
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
        addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent event) {
                recomputeOnResize();
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
        if (layoutWidth != getWidth() || layoutHeight != getHeight()) {
            recomputeLayout(getWidth(), getHeight(), assets);
        }

        Graphics2D g = (Graphics2D) graphics.create();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            for (Link link : links) drawLink(g, link);
            for (NetworkAsset asset : assets) drawNodeGlyph(g, asset);
            for (NetworkAsset asset : assets) drawHostName(g, asset);
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

    private void recomputeOnResize() {
        List<NetworkAsset> assets;
        try {
            assets = new ArrayList<>(network.getAssets());
        } catch (ConcurrentModificationException exception) {
            return;
        }
        recomputeLayout(getWidth(), getHeight(), assets);
        repaint();
    }

    private void recomputeLayout(int width, int height, List<NetworkAsset> currentAssets) {
        List<NetworkAsset> assets = new ArrayList<>(currentAssets);
        assets.sort(Comparator.comparing(NetworkAsset::getName).thenComparing(NetworkAsset::getId));
        EnumMap<AssetType, List<NetworkAsset>> groups = new EnumMap<>(AssetType.class);
        for (AssetType type : AssetType.values()) groups.put(type, new ArrayList<>());
        for (NetworkAsset asset : assets) groups.get(asset.getType()).add(asset);

        FontMetrics metrics = getFontMetrics(new Font("IBM Plex Mono", Font.PLAIN, 12));
        int labelHeight = metrics.getHeight() + 2;
        int rowStep = GLYPH_HALF_SIZE * 2 + LABEL_GAP + labelHeight + SLOT_GAP;
        Map<String, Integer> labelWidths = new HashMap<>();
        for (NetworkAsset asset : assets) labelWidths.put(asset.getId(), metrics.stringWidth(asset.getName()));

        int innerWidth = Math.max(1, width - 2 * PANEL_MARGIN);
        List<NetworkAsset> iot = groups.get(AssetType.IOT_DEVICE);
        List<NetworkAsset> workstations = groups.get(AssetType.WORKSTATION);
        List<NetworkAsset> routers = groups.get(AssetType.ROUTER);
        List<NetworkAsset> servers = groups.get(AssetType.SERVER);

        int iotSlotWidth = groupSlotWidth(iot, labelWidths);
        int serverSlotWidth = groupSlotWidth(servers, labelWidths);
        int iotColumns = Math.max(1, innerWidth / iotSlotWidth);
        int serverColumns = Math.max(1, innerWidth / serverSlotWidth);
        int iotRows = rowCount(iot.size(), iotColumns);
        int serverRows = rowCount(servers.size(), serverColumns);
        int topBandHeight = iotRows * rowStep;
        int bottomBandHeight = serverRows * rowStep;
        int middleTop = PANEL_MARGIN + topBandHeight;
        int middleBottom = height - PANEL_MARGIN - bottomBandHeight;
        int middleHeight = Math.max(rowStep, middleBottom - middleTop);

        int workstationSlotWidth = groupSlotWidth(workstations, labelWidths);
        int workstationRowsFit = Math.max(1, (middleHeight - GLYPH_HALF_SIZE * 2 - LABEL_GAP - labelHeight)
            / rowStep + 1);
        int requiredWorkstationColumns = Math.max(1, rowCount(workstations.size(), workstationRowsFit));
        int workstationColumnsFit = Math.max(1, (innerWidth / 2) / workstationSlotWidth);
        int workstationColumns = Math.min(requiredWorkstationColumns, workstationColumnsFit);
        int workstationRows = rowCount(workstations.size(), workstationColumns);
        int workstationZoneWidth = Math.min(innerWidth / 2, workstationColumns * workstationSlotWidth);
        int routerStartX = PANEL_MARGIN + workstationZoneWidth + SLOT_GAP;
        int routerZoneWidth = Math.max(1, width - PANEL_MARGIN - routerStartX);
        int routerSlotWidth = groupSlotWidth(routers, labelWidths);
        int routerColumns = Math.max(1, routerZoneWidth / routerSlotWidth);

        Map<String, Point> positions = new HashMap<>();
        Map<String, Rectangle> glyphs = new HashMap<>();
        Map<String, Rectangle> labels = new HashMap<>();
        placeRows(iot, iotColumns, PANEL_MARGIN, PANEL_MARGIN + GLYPH_HALF_SIZE, innerWidth,
            iotSlotWidth, labelWidths, metrics, width, rowStep, false, positions, glyphs, labels);
        placeColumns(workstations, workstationColumns, workstationRows, PANEL_MARGIN,
            middleTop + GLYPH_HALF_SIZE, workstationZoneWidth, workstationSlotWidth,
            labelWidths, metrics, width, rowStep, positions, glyphs, labels);
        placeRows(routers, routerColumns, routerStartX, middleTop + GLYPH_HALF_SIZE, routerZoneWidth,
            routerSlotWidth, labelWidths, metrics, width, rowStep, false, positions, glyphs, labels);
        int bottomCenterY = height - PANEL_MARGIN - GLYPH_HALF_SIZE - LABEL_GAP - labelHeight;
        placeRows(servers, serverColumns, PANEL_MARGIN, bottomCenterY, innerWidth, serverSlotWidth,
            labelWidths, metrics, width, rowStep, true,
            positions, glyphs, labels);

        layoutAssets = List.copyOf(assets);
        nodePositions = Map.copyOf(positions);
        nodeBounds = Map.copyOf(glyphs);
        labelBounds = Map.copyOf(labels);
        layoutWidth = width;
        layoutHeight = height;
    }

    private int groupSlotWidth(List<NetworkAsset> assets, Map<String, Integer> labelWidths) {
        int widest = 0;
        for (NetworkAsset asset : assets) widest = Math.max(widest, labelWidths.get(asset.getId()));
        return Math.max(48, widest + LABEL_PADDING * 2 + SLOT_GAP);
    }

    private int rowCount(int itemCount, int columns) {
        return itemCount == 0 ? 0 : (itemCount + columns - 1) / columns;
    }

    private void placeRows(List<NetworkAsset> assets, int columns, int zoneX, int firstCenterY, int zoneWidth,
                           int slotWidth, Map<String, Integer> widths, FontMetrics metrics, int panelWidth,
                           int rowStep, boolean fromBottom,
                           Map<String, Point> positions, Map<String, Rectangle> glyphs,
                           Map<String, Rectangle> labels) {
        if (assets.isEmpty()) return;
        int actualColumns = Math.max(1, Math.min(columns, Math.max(1, zoneWidth / slotWidth)));
        int rows = rowCount(assets.size(), actualColumns);
        int usedWidth = actualColumns * slotWidth;
        int startX = zoneX + Math.max(0, (zoneWidth - usedWidth) / 2);
        for (int index = 0; index < assets.size(); index++) {
            int row = index / actualColumns;
            int column = index % actualColumns;
            int centerX = startX + column * slotWidth + slotWidth / 2;
            int centerY = fromBottom
                    ? firstCenterY - row * rowStep
                    : firstCenterY + row * rowStep;
            place(assets.get(index), centerX, centerY, widths, metrics, panelWidth, positions, glyphs, labels);
        }
    }

    private void placeColumns(List<NetworkAsset> assets, int columns, int rows, int zoneX, int firstCenterY,
                              int zoneWidth, int slotWidth, Map<String, Integer> widths, FontMetrics metrics,
                              int panelWidth, int rowStep,
                              Map<String, Point> positions, Map<String, Rectangle> glyphs,
                              Map<String, Rectangle> labels) {
        if (assets.isEmpty()) return;
        int actualColumns = Math.max(1, columns);
        int actualRows = Math.max(1, rows);
        int startX = zoneX + Math.max(0, (zoneWidth - actualColumns * slotWidth) / 2);
        for (int index = 0; index < assets.size(); index++) {
            int column = index / actualRows;
            int row = index % actualRows;
            int centerX = startX + column * slotWidth + slotWidth / 2;
            int centerY = firstCenterY + row * rowStep;
            place(assets.get(index), centerX, centerY, widths, metrics, panelWidth, positions, glyphs, labels);
        }
    }

    private void place(NetworkAsset asset, int centerX, int centerY, Map<String, Integer> widths,
                       FontMetrics metrics, int panelWidth, Map<String, Point> positions,
                       Map<String, Rectangle> glyphs, Map<String, Rectangle> labels) {
        Point center = new Point(centerX, centerY);
        int labelWidth = widths.get(asset.getId()) + LABEL_PADDING * 2;
        int labelHeight = metrics.getHeight() + 2;
        int left = Math.max(PANEL_MARGIN, Math.min(centerX - labelWidth / 2,
            Math.max(PANEL_MARGIN, panelWidth - PANEL_MARGIN - labelWidth)));
        Rectangle label = new Rectangle(left, centerY + GLYPH_HALF_SIZE + LABEL_GAP,
                labelWidth, labelHeight);
        positions.put(asset.getId(), center);
        glyphs.put(asset.getId(), new Rectangle(centerX - GLYPH_HALF_SIZE, centerY - GLYPH_HALF_SIZE,
                GLYPH_HALF_SIZE * 2, GLYPH_HALF_SIZE * 2));
        labels.put(asset.getId(), label);
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

    private void drawNodeGlyph(Graphics2D g, NetworkAsset asset) {
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

    private void drawHostName(Graphics2D g, NetworkAsset asset) {
        Rectangle bounds = labelBounds.get(asset.getId());
        if (bounds == null) return;
        g.setColor(FOREST);
        g.fillRect(bounds.x, bounds.y, bounds.width, bounds.height);
        g.setColor(MUTED_ON_FOREST);
        g.setFont(new Font("IBM Plex Mono", Font.PLAIN, 12));
        FontMetrics metrics = g.getFontMetrics();
        g.drawString(asset.getName(), bounds.x + LABEL_PADDING, bounds.y + metrics.getAscent());
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
            recomputeLayout(getWidth(), getHeight(), assets);
        }
        NetworkAsset match = null;
        for (NetworkAsset asset : layoutAssets) {
            Rectangle bounds = nodeBounds.get(asset.getId());
            if (bounds != null && bounds.contains(x, y)) {
                match = asset;
                break;
            }
        }
        selectedAsset = match;
        hostPanel.showHost(match);
        repaint();
    }
}
