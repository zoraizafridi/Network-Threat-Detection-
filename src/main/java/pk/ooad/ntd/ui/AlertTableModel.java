package pk.ooad.ntd.ui;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import javax.swing.table.AbstractTableModel;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

public class AlertTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {"Time", "Severity", "Type", "Source", "Target"};
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");
    private final int maxRows;
    private final int maxPerSecond;
    private final Clock clock;
    private final List<AlertRow> rows = new ArrayList<>();
    private Severity severityFilter;
    private Instant activeSecond;
    private int acceptedThisSecond;
    private int similarAlerts;

    public AlertTableModel() {
        this(ConfigManager.getInstance().getInt("ui.alert.maxRows", 200),
                ConfigManager.getInstance().getInt("ui.alert.maxPerSecond", 10), Clock.systemDefaultZone());
    }

    AlertTableModel(int maxRows, int maxPerSecond, Clock clock) {
        if (maxRows < 1) throw new IllegalArgumentException("ui.alert.maxRows must be at least 1");
        if (maxPerSecond < 1) throw new IllegalArgumentException("ui.alert.maxPerSecond must be at least 1");
        this.maxRows = maxRows;
        this.maxPerSecond = maxPerSecond;
        this.clock = clock;
    }

    @Override
    public int getRowCount() {
        return filteredRows().size() + (similarAlerts > 0 ? 1 : 0);
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        List<AlertRow> visibleRows = filteredRows();
        if (rowIndex >= visibleRows.size()) {
            return columnIndex == 0 ? "+" + similarAlerts + " similar alerts" : "";
        }
        AlertRow row = visibleRows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.time;
            case 1 -> row.alert.getSeverity();
            case 2 -> row.alert.getAttackType().toString().replace('_', ' ');
            case 3 -> row.alert.getSourceIp();
            case 4 -> row.alert.getTargetIp();
            default -> throw new IndexOutOfBoundsException("Unknown alert column: " + columnIndex);
        };
    }

    public void addAlert(Alert alert) {
        if (alert == null) return;
        Instant now = clock.instant();
        Instant second = now.truncatedTo(ChronoUnit.SECONDS);
        if (!second.equals(activeSecond)) {
            activeSecond = second;
            acceptedThisSecond = 0;
            similarAlerts = 0;
        }
        if (acceptedThisSecond >= maxPerSecond) {
            similarAlerts++;
            fireTableDataChanged();
            return;
        }

        acceptedThisSecond++;
        String time = TIME_FORMAT.withZone(clock.getZone()).format(now);
        rows.add(0, new AlertRow(alert, time));
        while (rows.size() > maxRows) rows.remove(rows.size() - 1);
        fireTableDataChanged();
    }

    void setSeverityFilter(Severity severity) {
        severityFilter = severity;
        fireTableDataChanged();
    }

    Severity getSeverityFilter() {
        return severityFilter;
    }

    private List<AlertRow> filteredRows() {
        if (severityFilter == null) return rows;
        return rows.stream().filter(row -> row.alert.getSeverity() == severityFilter).toList();
    }

    private static final class AlertRow {
        private final Alert alert;
        private final String time;

        private AlertRow(Alert alert, String time) {
            this.alert = alert;
            this.time = time;
        }
    }
}
