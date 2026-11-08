package pk.ooad.ntd.security;

import pk.ooad.ntd.util.ConfigManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class SecurityPolicy {

    private record Account(String role, String usernameKey, String passwordKey, String envKey) {
    }

    private static final List<Account> ACCOUNTS = List.of(
            new Account("Admin", "auth.defaultUsername", "auth.defaultPassword", "NTD_ADMIN_PASSWORD"),
            new Account("Analyst", "auth.analystUsername", "auth.analystPassword", "NTD_ANALYST_PASSWORD"),
            new Account("Viewer", "auth.viewerUsername", "auth.viewerPassword", "NTD_VIEWER_PASSWORD"));

    private static final Set<String> SHIPPED_HASHES = Set.of(
            "pbkdf2$210000$06e745429c83c80a3fc869a46ad11d44$7bdc8198165b37bcbcbd85ca0e81fb1d0b43e6ab16dfaa6ddff77ec9ca2f03cc",
            "pbkdf2$210000$9fe0c4dd6dc698de4a587165061e6179$da5488e40056512150037a61998a2c7c97f5181fff6d33721f084aabb282fc54",
            "pbkdf2$210000$03be3e94f75c04fc651a74e0db5f1c85$494049a41d457eb385fe44006bd781df9921dc0d5a434d0243ee58cb25c3953e");

    private static final Set<String> DEMO_PASSWORDS = Set.of("admin", "analyst", "viewer");

    private final boolean demoMode;
    private final int minPasswordLength;
    private final boolean requireClasses;
    private final boolean secureCookie;

    private SecurityPolicy(boolean demoMode, int minPasswordLength, boolean requireClasses,
                           boolean secureCookie) {
        this.demoMode = demoMode;
        this.minPasswordLength = Math.max(8, minPasswordLength);
        this.requireClasses = requireClasses;
        this.secureCookie = secureCookie;
    }

    public static SecurityPolicy from(ConfigManager config) {
        return new SecurityPolicy(
                Boolean.parseBoolean(config.getString("app.demoMode", "true")),
                config.getInt("auth.password.minLength", 12),
                Boolean.parseBoolean(config.getString("auth.password.requireClasses", "true")),
                Boolean.parseBoolean(config.getString("auth.session.secureCookie", "false")));
    }

    public boolean demoMode() {
        return demoMode;
    }

    public List<String> startupProblems(ConfigManager config) {
        if (demoMode) {
            return List.of();
        }
        List<String> problems = new ArrayList<>();
        for (Account account : ACCOUNTS) {
            String username = config.getString(account.usernameKey(), "").trim();
            String credential = credentialFor(config, account);
            String label = account.role() + " (" + account.usernameKey() + ")";
            if (username.isEmpty()) {
                problems.add(label + " has no username");
                continue;
            }
            if (credential.isEmpty()) {
                problems.add(label + " has no credential");
            } else if (isShippedHash(credential)) {
                problems.add(label + " still holds the shipped demo credential; set "
                        + account.envKey() + " or replace the hash");
            } else if (!isHash(credential)) {
                String problem = passwordProblem(username, credential);
                if (problem != null) {
                    problems.add(label + " password " + problem);
                }
            }
        }
        return problems;
    }

    public List<String> warnings(ConfigManager config) {
        List<String> warnings = new ArrayList<>();
        if (!secureCookie) {
            warnings.add("the session cookie is not Secure; terminate TLS in front of the server "
                    + "and set auth.session.secureCookie=true");
        }
        if (!demoMode && Boolean.parseBoolean(config.getString("auth.reauth.enabled", "true"))
                && !Boolean.parseBoolean(config.getString("auth.csrf.enabled", "true"))) {
            warnings.add("CSRF protection is off while re-authentication is on");
        }
        if (demoMode) {
            warnings.add("demo mode is on: shipped credentials are accepted, so do not expose this server");
        }
        return warnings;
    }

    public String banner(String version) {
        String rule = "=".repeat(72);
        if (!demoMode) {
            return "";
        }
        return rule + "\n"
                + " DEMO MODE (" + version + ")\n"
                + "   Traffic is simulated. The accounts admin, analyst and viewer\n"
                + "   are enabled and each password is its username.\n"
                + "   Do not expose this server. To run for real, start with\n"
                + "   -Dntd.app.demoMode=false and set NTD_ADMIN_PASSWORD,\n"
                + "   NTD_ANALYST_PASSWORD and NTD_VIEWER_PASSWORD.\n"
                + rule;
    }

    public String passwordProblem(String username, String raw) {
        if (raw == null || raw.isBlank()) {
            return "is empty";
        }
        if (raw.length() < minPasswordLength) {
            return "is shorter than " + minPasswordLength + " characters";
        }
        if (username != null && !username.isBlank() && raw.equalsIgnoreCase(username)) {
            return "is the same as the username";
        }
        if (DEMO_PASSWORDS.contains(raw.toLowerCase(Locale.ROOT))) {
            return "is one of the shipped demo passwords";
        }
        if (requireClasses && !(raw.chars().anyMatch(Character::isLetter)
                && raw.chars().anyMatch(Character::isDigit))) {
            return "needs at least one letter and one digit";
        }
        return null;
    }

    public static String credentialFor(ConfigManager config, String passwordKey, String envKey) {
        String fromEnv = System.getenv(envKey);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv.trim();
        }
        return config.getString(passwordKey, "");
    }

    private static String credentialFor(ConfigManager config, Account account) {
        return credentialFor(config, account.passwordKey(), account.envKey());
    }

    private static boolean isShippedHash(String value) {
        return SHIPPED_HASHES.contains(value.trim());
    }

    private static boolean isHash(String value) {
        return value.startsWith("pbkdf2$") || value.contains("$")
                || value.matches("[0-9a-fA-F]{64}");
    }
}
