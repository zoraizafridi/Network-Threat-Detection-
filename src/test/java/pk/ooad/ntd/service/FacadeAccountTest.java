package pk.ooad.ntd.service;

import org.junit.jupiter.api.Test;
import pk.ooad.ntd.domain.Admin;
import pk.ooad.ntd.domain.Network;
import pk.ooad.ntd.domain.SecurityAnalyst;
import pk.ooad.ntd.domain.User;
import pk.ooad.ntd.domain.Viewer;
import pk.ooad.ntd.util.ConfigManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FacadeAccountTest {
    @Test
    void configuredAccountsAuthenticateWithRolePermissionsAndRejectInvalidCredentials() {
        IncidentResponseFacade facade = new IncidentResponseFacade(new Network(), 981L);

        User admin = facade.login("admin", "admin");
        assertInstanceOf(Admin.class, admin);
        assertTrue(admin.canConfigure());
        assertTrue(admin.canManageUsers());

        User analyst = facade.login("analyst", "analyst");
        assertInstanceOf(SecurityAnalyst.class, analyst);
        assertFalse(analyst.canConfigure());
        assertFalse(analyst.canManageUsers());

        User viewer = facade.login("viewer", "viewer");
        assertInstanceOf(Viewer.class, viewer);
        assertFalse(viewer.canConfigure());
        assertFalse(viewer.canManageUsers());

        assertThrows(IllegalArgumentException.class, () -> facade.login("analyst", "wrong"));
        assertThrows(IllegalArgumentException.class, () -> facade.login("unknown", "password"));
    }

    @Test
    void legacyDefaultCredentialsRemainAdminFallback() throws IOException {
        Path legacyConfig = Files.createTempFile("legacy-auth", ".properties");
        try {
            Files.writeString(legacyConfig, "auth.defaultUsername=legacy-root\nauth.defaultPassword=secret\n");
            ConfigManager.getInstance().load(legacyConfig.toString());
            IncidentResponseFacade facade = new IncidentResponseFacade(new Network(), 982L);
            assertInstanceOf(Admin.class, facade.login("legacy-root", "secret"));
        } finally {
            Files.deleteIfExists(legacyConfig);
            ConfigManager.getInstance().load("src/main/resources/config.properties");
        }
    }
}
