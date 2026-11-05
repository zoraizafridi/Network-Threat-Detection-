package pk.ooad.ntd.domain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public abstract class User {
    private final String username;
    private final String passwordHash;

    protected User(String username, String passwordHash) {
        this.username = Objects.requireNonNull(username, "username must not be null");
        this.passwordHash = passwordHash != null ? passwordHash : "";
    }

    public boolean checkPassword(String raw) {
        if (raw == null) {
            return false;
        }
        if (passwordHash.equals(raw)) {
            return true;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return passwordHash.equalsIgnoreCase(hex.toString());
        } catch (NoSuchAlgorithmException e) {
            return false;
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

