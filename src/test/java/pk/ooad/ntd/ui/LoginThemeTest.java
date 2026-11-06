package pk.ooad.ntd.ui;

import com.formdev.flatlaf.FlatLightLaf;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Admin;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.Viewer;
import pk.ooad.ntd.Main;
import pk.ooad.ntd.service.IncidentResponseFacade;

import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Font;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginThemeTest {
    @Test
    void mainFrameShowsAdminNavigationOnlyForUsersWhoCanManageUsers() {
        IncidentResponseFacade facade = new IncidentResponseFacade(new Network(), 7L);
        MainFrame frame = new MainFrame(facade);
        try {
            frame.applyRolePermissions(new Admin("admin", "hash"));
            assertTrue(frame.isAdminItemVisible());

            frame.applyRolePermissions(new Viewer("viewer", "hash"));
            assertFalse(frame.isAdminItemVisible());
        } finally {
            frame.dispose();
        }
    }

    @Test
    void applicationThemeRegistersLookAndFeelColorsAndClasspathFonts() throws Exception {
        Method configure = Main.class.getDeclaredMethod("configureLookAndFeel");
        configure.setAccessible(true);
        configure.invoke(null);

        assertInstanceOf(FlatLightLaf.class, UIManager.getLookAndFeel());
        assertEquals(new Color(0xE8DCC4), UIManager.getColor("Panel.background"));
        Font defaultFont = UIManager.getFont("defaultFont");
        Font monoFont = UIManager.getFont("TextArea.font");
        assertNotNull(defaultFont);
        assertNotNull(monoFont);
        assertEquals("IBM Plex Sans", defaultFont.getFamily());
        assertEquals("IBM Plex Mono", monoFont.getFamily());
        assertNotNull(Main.class.getClassLoader().getResource("fonts/IBMPlexSans-Regular.ttf"));
        assertNotNull(Main.class.getClassLoader().getResource("fonts/IBMPlexSans-SemiBold.ttf"));
        assertNotNull(Main.class.getClassLoader().getResource("fonts/IBMPlexMono-Regular.ttf"));
    }
}
