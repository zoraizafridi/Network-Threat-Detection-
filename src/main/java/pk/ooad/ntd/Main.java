package pk.ooad.ntd;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.ui.LoginFrame;

import javax.swing.UIManager;
import javax.swing.SwingUtilities;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.io.InputStream;
import java.awt.FontFormatException;

public class Main {
    public static void main(String[] args) {
        boolean headless = false;
        boolean web = false;
        for (String a : args) {
            if (a.equals("--headless")) headless = true;
            if (a.equals("--web")) web = true;
        }
        if (web) System.out.println("Web mode (to be built)");
        else if (headless) System.out.println("Headless mode (to be built)");
        else SwingUtilities.invokeLater(() -> {
            configureLookAndFeel();
            new LoginFrame(new IncidentResponseFacade()).setVisible(true);
        });
    }

    private static void configureLookAndFeel() {
        Font regular = loadFont("fonts/IBMPlexSans-Regular.ttf", Font.PLAIN);
        Font semibold = loadFont("fonts/IBMPlexSans-SemiBold.ttf", Font.BOLD);
        Font mono = loadFont("fonts/IBMPlexMono-Regular.ttf", Font.PLAIN);
        FlatLaf.registerCustomDefaultsSource("pk.ooad.ntd.ui.theme");
        FlatLightLaf.setup();

        UIManager.put("defaultFont", regular);
        UIManager.put("Label.font", regular);
        UIManager.put("Button.font", semibold);
        UIManager.put("TextField.font", regular);
        UIManager.put("PasswordField.font", regular);
        UIManager.put("TextArea.font", mono);
    }

    private static Font loadFont(String resource, int style) {
        Font fallback = new Font(Font.SANS_SERIF, style, 14);
        try (InputStream input = Main.class.getClassLoader().getResourceAsStream(resource)) {
            if (input == null) return fallback;
            Font font = Font.createFont(Font.TRUETYPE_FONT, input).deriveFont(style, 14f);
            GraphicsEnvironment.getLocalGraphicsEnvironment().registerFont(font);
            return font;
        } catch (FontFormatException | IOException | RuntimeException exception) {
            return fallback;
        }
    }
}