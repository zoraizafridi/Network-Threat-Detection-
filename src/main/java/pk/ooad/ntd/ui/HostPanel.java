package pk.ooad.ntd.ui;

import pk.ooad.ntd.domain.NetworkAsset;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Locale;

public class HostPanel extends JPanel {
    private static final Color INK = new Color(0x1F3D2B);
    private static final Color MUTED = new Color(0x4A5E4F);

    private final CardLayout cardLayout;
    private final JPanel cards;
    private final JLabel[] values;
    private final JLabel emptyMessage;

    public HostPanel() {
        super(new BorderLayout());
        cardLayout = new CardLayout();
        cards = new JPanel(cardLayout);
        cards.setOpaque(false);
        values = new JLabel[6];
        setOpaque(false);
        setBorder(BorderFactory.createEmptyBorder(0, 16, 0, 16));

        JPanel details = new JPanel(new GridBagLayout());
        details.setOpaque(false);
        String[] rowNames = {"Name", "IP", "Type", "Risk", "Status", "Last alert"};
        for (int row = 0; row < rowNames.length; row++) {
            GridBagConstraints constraints = new GridBagConstraints();
            constraints.gridy = row;
            constraints.insets = new Insets(8, 8, 8, 8);
            constraints.anchor = GridBagConstraints.NORTHWEST;
            constraints.fill = GridBagConstraints.HORIZONTAL;
            constraints.weightx = 0;
            constraints.gridx = 0;
            JLabel rowLabel = new JLabel(rowNames[row]);
            rowLabel.setName("host.row." + rowKey(rowNames[row]) + ".label");
            rowLabel.setForeground(INK);
            rowLabel.setFont(rowLabel.getFont().deriveFont(Font.PLAIN, 14f));
            details.add(rowLabel, constraints);

            constraints.gridx = 1;
            constraints.weightx = 1;
            JLabel value = new JLabel("");
            value.setName("host.row." + rowKey(rowNames[row]) + ".value");
            value.setForeground(INK);
            value.setFont(value.getFont().deriveFont(Font.PLAIN, 14f));
            if (row == 1 || row == 3 || row == 5) {
                value.setFont(new Font("IBM Plex Mono", Font.PLAIN, 14));
            }
            details.add(value, constraints);
            values[row] = value;
        }

        emptyMessage = new JLabel("No host selected", JLabel.CENTER);
        emptyMessage.setName("host.empty.message");
        emptyMessage.setForeground(MUTED);
        emptyMessage.setFont(emptyMessage.getFont().deriveFont(Font.PLAIN, 14f));
        JPanel empty = new JPanel(new BorderLayout());
        empty.setOpaque(false);
        empty.add(emptyMessage, BorderLayout.CENTER);

        cards.add(empty, "empty");
        cards.add(details, "details");
        add(cards, BorderLayout.CENTER);
        showHost(null);
    }

    public void showHost(NetworkAsset asset) {
        if (asset == null) {
            cardLayout.show(cards, "empty");
            return;
        }
        values[0].setText(asset.getName());
        values[1].setText(asset.getIp());
        values[2].setText(asset.getType().toString());
        values[3].setText(String.format(Locale.ROOT, "%.0f of 100", asset.getRiskScore()));
        values[4].setText(asset.getStatus().toString());
        values[4].setForeground(switch (asset.getStatus()) {
            case NORMAL -> new Color(0x2F6B45);
            case SUSPICIOUS -> new Color(0x7A4F08);
            case COMPROMISED -> new Color(0xA8321F);
        });
        values[5].setText("None");
        cardLayout.show(cards, "details");
    }

    private String rowKey(String rowName) {
        return rowName.toLowerCase(Locale.ROOT).replace(' ', '-');
    }
}
