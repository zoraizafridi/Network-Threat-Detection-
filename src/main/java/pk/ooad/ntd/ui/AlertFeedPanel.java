package pk.ooad.ntd.ui;

import pk.ooad.ntd.detection.AlertListener;
import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.util.ConfigManager;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.Clock;
import java.util.Objects;

public class AlertFeedPanel extends JPanel implements AlertListener {
    private static final Color GROUND = new Color(0xE8DCC4);
    private static final Color SURFACE = new Color(0xF3ECDD);
    private static final Color LINE = new Color(0xC9BA9A);
    private static final Color INK = new Color(0x1F3D2B);
    private static final Color MUTED = new Color(0x4A5E4F);
    private static final Color FOREST = new Color(0x1F3D2B);
    private static final Color SAND = new Color(0xE8DCC4);

    private final AlertTableModel tableModel;
    private final JTable table;
    private final JPanel cardPanel;
    private final CardLayout cardLayout;
    private final JButton[] filterButtons = new JButton[4];
    private final boolean showSeverityFilter;
    private Severity severityFilter;

    public AlertFeedPanel(IncidentResponseFacade facade) {
        this(facade, Clock.systemDefaultZone(),
                ConfigManager.getInstance().getInt("ui.alert.maxRows", 200),
                ConfigManager.getInstance().getInt("ui.alert.maxPerSecond", 10), true);
    }

    AlertFeedPanel(IncidentResponseFacade facade, Clock clock) {
        this(facade, clock, ConfigManager.getInstance().getInt("ui.alert.maxRows", 200),
                ConfigManager.getInstance().getInt("ui.alert.maxPerSecond", 10), true);
    }

    AlertFeedPanel(IncidentResponseFacade facade, Clock clock, int maxRows, int maxPerSecond) {
        this(facade, clock, maxRows, maxPerSecond, true);
    }

    AlertFeedPanel(IncidentResponseFacade facade, Clock clock, int maxRows, int maxPerSecond,
                   boolean showSeverityFilter) {
        super(new BorderLayout(0, 8));
        Objects.requireNonNull(facade, "facade must not be null");
        this.showSeverityFilter = showSeverityFilter;
        tableModel = new AlertTableModel(maxRows, maxPerSecond, Objects.requireNonNull(clock, "clock must not be null"));
        table = new JTable(tableModel);
        cardLayout = new CardLayout();
        cardPanel = new JPanel(cardLayout);
        buildPanel();
        facade.addAlertListener(this);
    }

    private void buildPanel() {
        setOpaque(false);
        setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        if (showSeverityFilter) add(buildFilterRow(), BorderLayout.NORTH);
        configureTable();

        JLabel emptyMessage = new JLabel("No alerts. Start the traffic.", JLabel.CENTER);
        emptyMessage.setName("alerts.empty.message");
        emptyMessage.setForeground(MUTED);
        emptyMessage.setFont(emptyMessage.getFont().deriveFont(Font.PLAIN, 14f));
        JPanel empty = new JPanel(new BorderLayout());
        empty.setBackground(SURFACE);
        empty.add(emptyMessage, BorderLayout.CENTER);
        cardPanel.add(empty, "empty");
        cardPanel.add(new JScrollPane(table), "table");
        add(cardPanel, BorderLayout.CENTER);
        updateEmptyState();
    }

    private JPanel buildFilterRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row.setOpaque(false);
        String[] names = {"All", "Low", "High", "Critical"};
        Severity[] severities = {null, Severity.LOW, Severity.HIGH, Severity.CRITICAL};
        for (int index = 0; index < names.length; index++) {
            JButton button = new JButton(names[index]);
            button.setName("alerts.filter." + names[index].toLowerCase());
            filterButtons[index] = button;
            styleFilter(button, index == 0);
            Severity selectedSeverity = severities[index];
            button.addActionListener(event -> setSeverityFilter(selectedSeverity));
            row.add(button);
        }
        return row;
    }

    private void configureTable() {
        table.setName("alerts.table");
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(32);
        table.setBackground(SURFACE);
        table.setForeground(INK);
        table.setGridColor(LINE);
        table.setShowGrid(false);
        table.setShowVerticalLines(false);
        table.setShowHorizontalLines(false);
        table.setIntercellSpacing(new java.awt.Dimension(0, 0));
        table.setAutoCreateRowSorter(false);
        table.setFont(table.getFont().deriveFont(Font.PLAIN, 13f));
        table.getTableHeader().setBackground(SURFACE);
        table.getTableHeader().setForeground(INK);
        table.getTableHeader().setFont(table.getFont().deriveFont(Font.PLAIN, 13f));
        table.getTableHeader().setReorderingAllowed(false);
        for (int index = 0; index < table.getColumnModel().getColumnCount(); index++) {
            TableColumn column = table.getColumnModel().getColumn(index);
            if (index == 1) column.setCellRenderer(new SeverityRenderer());
            else column.setCellRenderer(new TextRenderer(index == 0 || index >= 3));
        }
        table.getColumnModel().getColumn(0).setPreferredWidth(76);
        table.getColumnModel().getColumn(1).setPreferredWidth(96);
        table.getColumnModel().getColumn(2).setPreferredWidth(100);
        table.getColumnModel().getColumn(3).setPreferredWidth(112);
        table.getColumnModel().getColumn(4).setPreferredWidth(112);
    }

    private void setSeverityFilter(Severity filter) {
        severityFilter = filter;
        tableModel.setSeverityFilter(filter);
        for (int index = 0; index < filterButtons.length; index++) {
            boolean selected = index == 0 ? filter == null : filter != null
                    && filter.name().equalsIgnoreCase(filterButtons[index].getText());
            styleFilter(filterButtons[index], selected);
        }
        updateEmptyState();
    }

    private void styleFilter(JButton button, boolean selected) {
        button.setOpaque(true);
        button.setContentAreaFilled(true);
        button.setFocusPainted(false);
        button.setFont(button.getFont().deriveFont(Font.PLAIN, 13f));
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(selected ? FOREST : LINE, 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        button.setBackground(selected ? FOREST : GROUND);
        button.setForeground(selected ? SAND : INK);
    }

    @Override
    public void onAlert(Alert alert) {
        SwingUtilities.invokeLater(() -> {
            if (!isDisplayable()) return;
            tableModel.addAlert(alert);
            updateEmptyState();
        });
    }

    private void updateEmptyState() {
        cardLayout.show(cardPanel, tableModel.getRowCount() == 0 ? "empty" : "table");
        cardPanel.revalidate();
        cardPanel.repaint();
    }

    AlertTableModel tableModel() {
        return tableModel;
    }

    Severity severityFilter() {
        return severityFilter;
    }

    private static final class TextRenderer extends DefaultTableCellRenderer {
        private final boolean mono;

        private TextRenderer(boolean mono) {
            this.mono = mono;
            setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, LINE));
            setBackground(SURFACE);
            setForeground(INK);
            setFont(getFont().deriveFont(Font.PLAIN, 13f));
        }

        @Override
        public Component getTableCellRendererComponent(JTable source, Object value, boolean selected,
                                                       boolean focused, int row, int column) {
            super.getTableCellRendererComponent(source, value, false, false, row, column);
            setBackground(SURFACE);
            setForeground(value instanceof String text && text.startsWith("+") ? MUTED : INK);
            setFont(mono ? new Font("IBM Plex Mono", Font.PLAIN, 13)
                    : getFont().deriveFont(Font.PLAIN, 13f));
            setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 1, 0, LINE),
                    BorderFactory.createEmptyBorder(0, 4, 0, 4)));
            return this;
        }
    }

    private static final class SeverityRenderer extends JPanel implements TableCellRenderer {
        private final JLabel text = new JLabel();
        private final SeveritySquare square = new SeveritySquare();

        private SeverityRenderer() {
            super(new FlowLayout(FlowLayout.LEFT, 4, 0));
            setOpaque(true);
            setBackground(SURFACE);
            setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, LINE));
            text.setFont(text.getFont().deriveFont(Font.PLAIN, 13f));
            text.setForeground(INK);
            add(text);
            add(square);
        }

        @Override
        public Component getTableCellRendererComponent(JTable source, Object value, boolean selected,
                                                       boolean focused, int row, int column) {
            if (value instanceof Severity severity) {
                text.setText(severity.toString());
                square.setSeverity(severity);
                square.setVisible(true);
            } else {
                text.setText(value == null ? "" : value.toString());
                text.setForeground(value instanceof String display && display.startsWith("+") ? MUTED : INK);
                square.setVisible(false);
            }
            setBackground(SURFACE);
            return this;
        }
    }

    private static final class SeveritySquare extends JPanel {
        private SeveritySquare() {
            setOpaque(true);
            setPreferredSize(new java.awt.Dimension(8, 8));
        }

        private void setSeverity(Severity severity) {
            setBackground(switch (severity) {
                case LOW -> new Color(0x3F6182);
                case HIGH -> new Color(0x7A4F08);
                case CRITICAL -> new Color(0xA8321F);
            });
        }
    }
}
