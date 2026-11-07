package pk.ooad.ntd.domain;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public abstract class User {
    private static final String PBKDF2_PREFIX = "pbkdf2$";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int PBKDF2_KEY_BITS = 256;
    private static final int SALT_BYTES = 16;

    private final String username;
    private final String passwordHash;

    protected User(String username, String passwordHash) {
        this.username = Objects.requireNonNull(username, "username must not be null");
        this.passwordHash = passwordHash != null ? passwordHash : "";
    }

    public static String hashPassword(String raw) {
        Objects.requireNonNull(raw, "raw password must not be null");
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        byte[] derived = pbkdf2(raw, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BITS);
        HexFormat hex = HexFormat.of();
        return PBKDF2_PREFIX + PBKDF2_ITERATIONS + "$" + hex.formatHex(salt) + "$" + hex.formatHex(derived);
    }

    public boolean checkPassword(String raw) {
        if (raw == null || passwordHash.isEmpty()) {
            return false;
        }
        if (passwordHash.startsWith(PBKDF2_PREFIX)) {
            return checkPbkdf2(raw, passwordHash);
        }
        if (passwordHash.equals(raw)) {
            return true;
        }
        if (passwordHash.contains("$")) {
            String[] parts = passwordHash.split("\\$");
            if (parts.length == 2) {
                return parts[1].equalsIgnoreCase(sha256(parts[0] + raw));
            } else if (parts.length == 3 && parts[0].equalsIgnoreCase("sha256")) {
                return parts[2].equalsIgnoreCase(sha256(parts[1] + raw));
            }
        }
        return passwordHash.equalsIgnoreCase(sha256(raw));
    }

    public boolean usesLegacyHash() {
        return !passwordHash.startsWith(PBKDF2_PREFIX);
    }

    private static boolean checkPbkdf2(String raw, String stored) {
        String[] parts = stored.split("\\$");
        if (parts.length != 4) {
            return false;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        if (iterations < 1) {
            return false;
        }
        byte[] salt;
        byte[] expected;
        try {
            salt = HexFormat.of().parseHex(parts[2]);
            expected = HexFormat.of().parseHex(parts[3]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (expected.length == 0) {
            return false;
        }
        byte[] actual = pbkdf2(raw, salt, iterations, expected.length * 8);
        return MessageDigest.isEqual(expected, actual);
    }

    private static byte[] pbkdf2(String raw, byte[] salt, int iterations, int keyBits) {
        PBEKeySpec spec = new PBEKeySpec(raw.toCharArray(), salt, iterations, keyBits);
        try {
            return SecretKeyFactory.getInstance(PBKDF2_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to derive password hash", e);
        } finally {
            spec.clearPassword();
        }
    }

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    public abstract boolean canLaunchAttack();

    public abstract boolean canRunPlanner();

    public abstract boolean canConfigure();

    public abstract boolean canManageUsers();

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(username, user.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "username='" + username + '\'' +
                '}';
    }
}

