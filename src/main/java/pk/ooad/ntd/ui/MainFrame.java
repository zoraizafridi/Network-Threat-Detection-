package pk.ooad.ntd.ui;

import pk.ooad.ntd.domain.User;
import pk.ooad.ntd.domain.AssetStatus;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.service.IncidentResponseFacade;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.swing.SwingUtilities;

public class MainFrame extends JFrame {
    private static final Color GROUND = new Color(0xE8DCC4);
    private static final Color FOREST = new Color(0x1F3D2B);
    private static final Color FOREST_RAISED = new Color(0x2A4F39);
    private static final Color FOREST_LINE = new Color(0x3E6650);
    private static final Color SAND_TEXT = new Color(0xE8DCC4);
    private static final int SIDEBAR_WIDTH = 240;
    private static final String[] SCREEN_NAMES = {"Monitor", "Alerts", "Control", "Planner", "Report", "Admin"};

    private final IncidentResponseFacade facade;
    private final JPanel sidebar;
    private final JPanel contentPanel;
    private final JPanel screenCards;
    private final CardLayout cardLayout;
    private final List<JButton> navigationItems;
    private final JLabel usernameLabel;
    private final MetricStrip metricStrip;
    private final JPanel monitorScreen;
    private final NetworkMapPanel networkMapPanel;
    private final HostPanel hostPanel;
    private final AlertFeedPanel monitorAlertFeed;
    private final AlertFeedPanel alertsScreenFeed;
    private int activeAlertCount;
    private JButton selectedItem;

    public MainFrame(IncidentResponseFacade facade) {
        super("Network Threat Detection");
        this.facade = Objects.requireNonNull(facade, "facade must not be null");
        sidebar = new JPanel();
        contentPanel = new JPanel(new BorderLayout());
        screenCards = new JPanel();
        cardLayout = new CardLayout();
        navigationItems = new ArrayList<>();
        usernameLabel = new JLabel(" ");
        metricStrip = new MetricStrip();
        monitorScreen = new JPanel(new BorderLayout());
        hostPanel = new HostPanel();
        networkMapPanel = new NetworkMapPanel(facade, hostPanel);
        monitorAlertFeed = new AlertFeedPanel(facade);
        alertsScreenFeed = new AlertFeedPanel(facade);
        buildShell();
        refreshMonitor();
        facade.addAlertListener(alert -> SwingUtilities.invokeLater(() -> {
            if (!isDisplayable()) return;
            activeAlertCount++;
            refreshMonitor();
            monitorScreen.revalidate();
            monitorScreen.repaint();
        }));
    }

    private void buildShell() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(960, 640));
        setSize(1100, 720);
        setLocationRelativeTo(null);
        getContentPane().setLayout(new BorderLayout());
        getContentPane().setBackground(GROUND);

        buildSidebar();
        buildScreens();
        add(sidebar, BorderLayout.WEST);
        add(contentPanel, BorderLayout.CENTER);
        showScreen("Monitor");
    }

    private void buildSidebar() {
        sidebar.setBackground(FOREST);
        sidebar.setPreferredSize(new Dimension(SIDEBAR_WIDTH, 0));
        sidebar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 0, 1, FOREST_LINE),
                BorderFactory.createEmptyBorder(24, 16, 16, 16)));
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));

        JPanel navigation = new JPanel();
        navigation.setOpaque(false);
        navigation.setLayout(new BoxLayout(navigation, BoxLayout.Y_AXIS));
        for (String screenName : SCREEN_NAMES) {
            JButton item = createNavigationItem(screenName);
            if (screenName.equals("Admin")) item.setVisible(false);
            navigationItems.add(item);
            navigation.add(item);
            navigation.add(Box.createVerticalStrut(8));
        }
        sidebar.add(navigation);
        sidebar.add(Box.createVerticalGlue());

        usernameLabel.setForeground(SAND_TEXT);
        usernameLabel.setFont(usernameLabel.getFont().deriveFont(Font.PLAIN, 14f));
        usernameLabel.setBorder(BorderFactory.createEmptyBorder(0, 8, 8, 8));
        usernameLabel.setAlignmentX(LEFT_ALIGNMENT);
        sidebar.add(usernameLabel);

        JButton signOut = new JButton("Sign out");
        styleNavigation(signOut, false);
        signOut.setAlignmentX(LEFT_ALIGNMENT);
        signOut.addActionListener(event -> this.facade.stop());
        sidebar.add(signOut);
    }

    private JButton createNavigationItem(String screenName) {
        JButton item = new JButton(screenName);
        item.setHorizontalAlignment(SwingConstants.LEFT);
        item.setAlignmentX(LEFT_ALIGNMENT);
        item.setMaximumSize(new Dimension(Integer.MAX_VALUE, 48));
        styleNavigation(item, false);
        item.addActionListener(event -> showScreen(screenName));
        item.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent event) {
                if (item != selectedItem) {
                    item.setBackground(FOREST_RAISED);
                    item.setForeground(SAND_TEXT);
                }
            }

            @Override
            public void mouseExited(MouseEvent event) {
                if (item != selectedItem) styleNavigation(item, false);
            }
        });
        return item;
    }

    private void styleNavigation(JButton item, boolean selected) {
        item.setOpaque(true);
        item.setContentAreaFilled(true);
        item.setFocusPainted(false);
        item.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        item.setFont(item.getFont().deriveFont(Font.PLAIN, 14f));
        item.setBackground(selected ? GROUND : FOREST);
        item.setForeground(selected ? FOREST : SAND_TEXT);
    }

    private void buildScreens() {
        screenCards.setLayout(cardLayout);
        screenCards.setBackground(GROUND);
        for (String name : SCREEN_NAMES) {
            if (name.equals("Monitor")) {
                buildMonitorScreen();
                screenCards.add(monitorScreen, name);
                continue;
            }
            if (name.equals("Alerts")) {
                JPanel alertsScreen = new JPanel(new BorderLayout());
                alertsScreen.setBackground(GROUND);
                alertsScreen.setBorder(BorderFactory.createEmptyBorder(24, 24, 24, 24));
                alertsScreen.add(alertsScreenFeed, BorderLayout.CENTER);
                screenCards.add(alertsScreen, name);
                continue;
            }
            JPanel placeholder = new JPanel(new BorderLayout());
            placeholder.setBackground(GROUND);
            placeholder.setBorder(BorderFactory.createEmptyBorder(24, 32, 24, 32));
            JLabel title = new JLabel(name);
            title.setForeground(FOREST);
            title.setFont(title.getFont().deriveFont(Font.PLAIN, 20f));
            placeholder.add(title, BorderLayout.NORTH);
            screenCards.add(placeholder, name);
        }
        contentPanel.setBackground(GROUND);
        contentPanel.add(screenCards, BorderLayout.CENTER);
    }

    private void buildMonitorScreen() {
        monitorScreen.setName("monitor.screen");
        monitorScreen.setBackground(GROUND);
        monitorScreen.setBorder(BorderFactory.createEmptyBorder(24, 24, 24, 24));
        monitorScreen.add(metricStrip, BorderLayout.NORTH);

        JPanel body = new JPanel(new GridBagLayout());
        body.setName("monitor.body");
        body.setBackground(GROUND);
        networkMapPanel.setName("monitor.network-map");
        networkMapPanel.setMinimumSize(new Dimension(0, 0));
        networkMapPanel.setPreferredSize(new Dimension(0, 0));
        hostPanel.setName("monitor.host-panel");
        hostPanel.setMinimumSize(new Dimension(0, 0));
        hostPanel.setPreferredSize(new Dimension(0, 0));
        GridBagConstraints mapConstraints = new GridBagConstraints();
        mapConstraints.gridx = 0;
        mapConstraints.gridy = 0;
        mapConstraints.weightx = 0.67;
        mapConstraints.weighty = 1;
        mapConstraints.fill = GridBagConstraints.BOTH;
        mapConstraints.insets = new java.awt.Insets(24, 0, 0, 32);
        body.add(networkMapPanel, mapConstraints);

        GridBagConstraints hostConstraints = new GridBagConstraints();
        hostConstraints.gridx = 1;
        hostConstraints.gridy = 0;
        hostConstraints.weightx = 0.33;
        hostConstraints.weighty = 1;
        hostConstraints.fill = GridBagConstraints.BOTH;
        hostConstraints.insets = new java.awt.Insets(24, 0, 0, 0);
        JPanel rightColumn = new JPanel(new BorderLayout(0, 16));
        rightColumn.setName("monitor.right-column");
        rightColumn.setOpaque(false);
        rightColumn.setMinimumSize(new Dimension(0, 0));
        rightColumn.setPreferredSize(new Dimension(0, 0));
        rightColumn.add(monitorAlertFeed, BorderLayout.CENTER);
        rightColumn.add(hostPanel, BorderLayout.SOUTH);
        body.add(rightColumn, hostConstraints);
        monitorScreen.add(body, BorderLayout.CENTER);
    }

    private void refreshMonitor() {
        Network network = facade.getNetwork();
        long hosts = network.getAssets().size();
        long compromisedHosts = network.getAssets().stream()
                .filter(asset -> asset.getStatus() == AssetStatus.COMPROMISED)
                .count();
        long compromisedLinks = network.getCompromisedLinks().size();
        metricStrip.update(hosts, activeAlertCount, compromisedHosts, compromisedLinks);
    }

    private void showScreen(String name) {
        cardLayout.show(screenCards, name);
        for (JButton item : navigationItems) {
            boolean selected = item.getText().equals(name);
            styleNavigation(item, selected);
            if (selected) selectedItem = item;
        }
    }

    public void applyRolePermissions(User user) {
        boolean canManageUsers = user != null && user.canManageUsers();
        JButton adminItem = navigationItems.get(navigationItems.size() - 1);
        adminItem.setVisible(canManageUsers);
        usernameLabel.setText(user == null ? "" : user.getUsername());
        if (!canManageUsers && adminItem == selectedItem) showScreen("Monitor");
        sidebar.revalidate();
        sidebar.repaint();
    }

    boolean isAdminItemVisible() {
        return navigationItems.get(navigationItems.size() - 1).isVisible();
    }

    HostPanel hostPanel() {
        return hostPanel;
    }

    AlertFeedPanel monitorAlertFeed() {
        return monitorAlertFeed;
    }

    AlertFeedPanel alertsScreenFeed() {
        return alertsScreenFeed;
    }

    private static final class MetricStrip extends JPanel {
        private static final Color LINE = new Color(0xC9BA9A);
        private static final Color INK = new Color(0x1F3D2B);
        private final JLabel[] figures = new JLabel[4];

        private MetricStrip() {
            super();
            setName("monitor.metric-strip");
            setOpaque(false);
            setLayout(new GridLayout(1, 4));
            String[] labels = {"Hosts", "Active alerts", "Hosts compromised", "Links compromised"};
            for (int index = 0; index < labels.length; index++) {
                JPanel figure = new JPanel();
                figure.setName("monitor.metric.column." + index);
                figure.setOpaque(false);
                figure.setLayout(new BoxLayout(figure, BoxLayout.Y_AXIS));
                if (index < labels.length - 1) {
                    figure.setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(0, 0, 0, 1, LINE),
                            BorderFactory.createEmptyBorder(0, 16, 16, 16)));
                } else {
                    figure.setBorder(BorderFactory.createEmptyBorder(0, 16, 16, 16));
                }
                figures[index] = new JLabel("0");
                figures[index].setName("monitor.metric." + index + ".value");
                figures[index].setForeground(INK);
                figures[index].setFont(new Font("IBM Plex Mono", Font.PLAIN, 28));
                JLabel label = new JLabel(labels[index]);
                label.setName("monitor.metric." + index + ".label");
                label.setForeground(INK);
                label.setFont(label.getFont().deriveFont(Font.PLAIN, 12f));
                figures[index].setAlignmentX(LEFT_ALIGNMENT);
                label.setAlignmentX(LEFT_ALIGNMENT);
                figure.add(figures[index]);
                figure.add(Box.createVerticalStrut(4));
                figure.add(label);
                add(figure);
            }
        }

        private void update(long hosts, int alerts, long compromisedHosts, long compromisedLinks) {
            long[] values = {hosts, alerts, compromisedHosts, compromisedLinks};
            for (int index = 0; index < values.length; index++) {
                figures[index].setText(Long.toString(values[index]));
            }
        }
    }
}
