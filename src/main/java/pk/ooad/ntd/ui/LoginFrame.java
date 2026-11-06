package pk.ooad.ntd.ui;

import pk.ooad.ntd.domain.User;
import pk.ooad.ntd.service.IncidentResponseFacade;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

public class LoginFrame extends JFrame {
    private static final Color GROUND = new Color(0xE8DCC4);
    private static final Color SURFACE = new Color(0xF3ECDD);
    private static final Color LINE = new Color(0xC9BA9A);
    private static final Color INK = new Color(0x1F3D2B);
    private static final Color ERROR = new Color(0xA8321F);

    private final JTextField usernameField;
    private final JPasswordField passwordField;
    private final IncidentResponseFacade facade;
    private final JLabel messageLabel;

    public LoginFrame(IncidentResponseFacade facade) {
        super("Network Threat Detection");
        this.facade = facade;
        usernameField = new JTextField();
        passwordField = new JPasswordField();
        messageLabel = new JLabel(" ", SwingConstants.LEFT);
        buildForm();
    }

    private void buildForm() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(560, 480));
        setSize(720, 560);
        setLocationRelativeTo(null);
        getContentPane().setBackground(GROUND);
        getContentPane().setLayout(new BorderLayout());

        JPanel form = new JPanel(new GridBagLayout());
        form.setBackground(GROUND);
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.insets = new Insets(0, 0, 8, 0);

        JLabel title = new JLabel("Network Threat Detection");
        title.setForeground(INK);
        title.setFont(UIManager.getFont("Button.font").deriveFont(20f));
        constraints.gridy = 0;
        constraints.insets = new Insets(0, 0, 24, 0);
        form.add(title, constraints);

        JLabel usernameLabel = new JLabel("Username");
        usernameLabel.setForeground(INK);
        usernameLabel.setFont(usernameLabel.getFont().deriveFont(Font.PLAIN, 14f));
        constraints.gridy = 1;
        constraints.insets = new Insets(0, 0, 8, 0);
        form.add(usernameLabel, constraints);

        styleInput(usernameField);
        constraints.gridy = 2;
        constraints.insets = new Insets(0, 0, 16, 0);
        form.add(usernameField, constraints);

        JLabel passwordLabel = new JLabel("Password");
        passwordLabel.setForeground(INK);
        passwordLabel.setFont(passwordLabel.getFont().deriveFont(Font.PLAIN, 14f));
        constraints.gridy = 3;
        constraints.insets = new Insets(0, 0, 8, 0);
        form.add(passwordLabel, constraints);

        styleInput(passwordField);
        constraints.gridy = 4;
        constraints.insets = new Insets(0, 0, 12, 0);
        form.add(passwordField, constraints);

        messageLabel.setForeground(ERROR);
        messageLabel.setFont(messageLabel.getFont().deriveFont(Font.PLAIN, 12f));
        constraints.gridy = 5;
        constraints.insets = new Insets(0, 0, 12, 0);
        form.add(messageLabel, constraints);

        JButton signInButton = new JButton("Sign in");
        signInButton.setBackground(INK);
        signInButton.setForeground(GROUND);
        signInButton.setFont(signInButton.getFont().deriveFont(Font.BOLD, 14f));
        signInButton.setFocusPainted(true);
        signInButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(INK, 1), BorderFactory.createEmptyBorder(8, 12, 8, 12)));
        signInButton.addActionListener(event -> onLoginClicked());
        constraints.gridy = 6;
        constraints.insets = new Insets(0, 0, 0, 0);
        form.add(signInButton, constraints);
        getRootPane().setDefaultButton(signInButton);

        JPanel center = new JPanel(new GridBagLayout());
        center.setBackground(GROUND);
        GridBagConstraints centerConstraints = new GridBagConstraints();
        centerConstraints.fill = GridBagConstraints.NONE;
        centerConstraints.anchor = GridBagConstraints.CENTER;
        centerConstraints.weightx = 0;
        centerConstraints.insets = new Insets(0, 16, 0, 16);
        center.add(form, centerConstraints);
        getContentPane().add(center, BorderLayout.CENTER);
    }

    private void styleInput(JTextField field) {
        field.setBackground(SURFACE);
        field.setForeground(INK);
        field.setCaretColor(INK);
        field.setFont(field.getFont().deriveFont(Font.PLAIN, 14f));
        field.setPreferredSize(new Dimension(320, 48));
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(LINE, 1), BorderFactory.createEmptyBorder(8, 12, 8, 12)));
    }

    public void onLoginClicked() {
        try {
            User user = facade.login(usernameField.getText(), new String(passwordField.getPassword()));
            MainFrame mainFrame = new MainFrame(facade);
            mainFrame.applyRolePermissions(user);
            mainFrame.setVisible(true);
            dispose();
        } catch (RuntimeException exception) {
            messageLabel.setText("Access denied");
            usernameField.requestFocusInWindow();
        }
    }
}
