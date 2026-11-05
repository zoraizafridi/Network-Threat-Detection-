package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserTest {

    @Test
    @DisplayName("Positive: Admin has all permissions true")
    void testAdminPermissions() {
        Admin admin = new Admin("admin", "adminPass");
        assertEquals("admin", admin.getUsername());
        assertTrue(admin.canLaunchAttack());
        assertTrue(admin.canRunPlanner());
        assertTrue(admin.canConfigure());
        assertTrue(admin.canManageUsers());
    }

    @Test
    @DisplayName("Positive: SecurityAnalyst has launch and plan true, configure and manage false")
    void testSecurityAnalystPermissions() {
        SecurityAnalyst analyst = new SecurityAnalyst("analyst", "analystPass");
        assertEquals("analyst", analyst.getUsername());
        assertTrue(analyst.canLaunchAttack());
        assertTrue(analyst.canRunPlanner());
        assertFalse(analyst.canConfigure());
        assertFalse(analyst.canManageUsers());
    }

    @Test
    @DisplayName("Positive: Viewer has all permissions false")
    void testViewerPermissions() {
        Viewer viewer = new Viewer("viewer", "viewPass");
        assertEquals("viewer", viewer.getUsername());
        assertFalse(viewer.canLaunchAttack());
        assertFalse(viewer.canRunPlanner());
        assertFalse(viewer.canConfigure());
        assertFalse(viewer.canManageUsers());
    }

    @Test
    @DisplayName("Password checking: Plaintext and SHA-256 hashed password verification")
    void testPasswordChecking() {
        // SHA-256 for "secret"
        String sha256OfSecret = "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b";
        Admin userWithHash = new Admin("alice", sha256OfSecret);

        assertTrue(userWithHash.checkPassword("secret"), "SHA-256 raw password must match hash");
        assertFalse(userWithHash.checkPassword("wrong"), "Incorrect password must return false");
        assertFalse(userWithHash.checkPassword(null), "Null password must return false");
        assertFalse(userWithHash.checkPassword(""), "Empty password must return false");

        // Plaintext fallback
        Viewer plainUser = new Viewer("bob", "plainP@ss");
        assertTrue(plainUser.checkPassword("plainP@ss"), "Direct password match supported");
        assertFalse(plainUser.checkPassword("other"), "Wrong password must return false");
    }

    @Test
    @DisplayName("AuthenticationException: Instantiation with message and cause")
    void testAuthenticationException() {
        AuthenticationException ex1 = new AuthenticationException("Bad credentials");
        assertEquals("Bad credentials", ex1.getMessage());

        Throwable cause = new IllegalArgumentException("Invalid state");
        AuthenticationException ex2 = new AuthenticationException("Auth failed", cause);
        assertEquals("Auth failed", ex2.getMessage());
        assertEquals(cause, ex2.getCause());
    }

    @Test
    @DisplayName("Negative and Edge: Null username, equals and hashCode")
    void testUserValidationAndEquality() {
        assertThrows(NullPointerException.class, () -> new Admin(null, "hash"));

        Admin u1 = new Admin("user1", "hash1");
        Admin u2 = new Admin("user1", "hash2");
        Admin u3 = new Admin("user2", "hash1");

        assertEquals(u1, u2);
        assertEquals(u1.hashCode(), u2.hashCode());
        assertNotEquals(u1, u3);
        assertNotEquals(u1, null);
        assertNotNull(u1.toString());
    }
}
