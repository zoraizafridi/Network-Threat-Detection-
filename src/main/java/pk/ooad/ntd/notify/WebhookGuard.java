package pk.ooad.ntd.notify;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;

public final class WebhookGuard {

    public record Verdict(URI uri, String refusal) {
        public boolean allowed() {
            return refusal == null;
        }
    }

    private WebhookGuard() {
    }

    public static Verdict check(String url, boolean allowInsecure) {
        if (url == null || url.isBlank()) {
            return new Verdict(null, "no webhook configured");
        }
        URI uri;
        try {
            uri = URI.create(url.trim());
        } catch (IllegalArgumentException ex) {
            return new Verdict(null, "malformed url");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return new Verdict(null, "malformed url");
        }
        if (uri.getUserInfo() != null) {
            return new Verdict(null, "credentials in the url are refused");
        }
        boolean insecureAllowedHere = allowInsecure && isLoopbackName(host);
        if (!"https".equals(scheme) && !(insecureAllowedHere && "http".equals(scheme))) {
            return new Verdict(null, "https is required; set notifications.allowInsecure for a loopback receiver");
        }
        try {
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isBlocked(address) && !insecureAllowedHere) {
                    return new Verdict(null, "refused address " + address.getHostAddress() + " for " + host);
                }
            }
        } catch (UnknownHostException ex) {
            return new Verdict(null, "host does not resolve: " + host);
        }
        return new Verdict(uri, null);
    }

    private static boolean isLoopbackName(String host) {
        String lower = host.toLowerCase(Locale.ROOT);
        if (lower.equals("localhost") || lower.endsWith(".localhost")) {
            return true;
        }
        try {
            return InetAddress.getByName(host).isLoopbackAddress();
        } catch (UnknownHostException ex) {
            return false;
        }
    }

    static boolean isBlocked(InetAddress address) {
        return address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()
                || isUniqueLocalIpv6(address);
    }

    private static boolean isUniqueLocalIpv6(InetAddress address) {
        byte[] bytes = address.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }

    static String signature(String body, String secret) {
        if (secret == null || secret.isBlank()) {
            return null;
        }
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    "HmacSHA256"));
            return "sha256=" + java.util.HexFormat.of().formatHex(mac.doFinal(
                    body.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException ex) {
            return null;
        }
    }
}
