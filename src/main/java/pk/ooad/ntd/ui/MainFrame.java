package pk.ooad.ntd.ui;

import pk.ooad.ntd.domain.User;

import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.Dimension;

public class MainFrame extends JFrame {
    private final JTabbedPane tabs;

    public MainFrame() {
        super("Network Threat Detection");
        tabs = new JTabbedPane();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        add(tabs, BorderLayout.CENTER);
        setMinimumSize(new Dimension(960, 640));
        setSize(1100, 720);
        setLocationRelativeTo(null);
    }

    public void applyRolePermissions(User user) {
        // The main screen remains an empty placeholder until its specified panels are implemented.
    }
}
