package pk.ooad.ntd.detection;

import pk.ooad.ntd.domain.Alert;
import pk.ooad.ntd.domain.AttackType;
import pk.ooad.ntd.domain.NetworkEvent;
import pk.ooad.ntd.domain.Severity;
import pk.ooad.ntd.util.ConfigManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

public class SignatureDetector extends Detector {
    private final Set<String> badIps;
    private final Set<Integer> badPorts;
    private final List<Pattern> payloadPatterns;

    public SignatureDetector(String name, Set<String> badIps, Set<Integer> badPorts, List<Pattern> payloadPatterns) {
        super(name != null ? name : "SignatureDetector");
        this.badIps = badIps != null ? new HashSet<>(badIps) : new HashSet<>();
        this.badPorts = badPorts != null ? new HashSet<>(badPorts) : new HashSet<>();
        this.payloadPatterns = payloadPatterns != null ? new ArrayList<>(payloadPatterns) : new ArrayList<>();
    }

    public SignatureDetector() {
        this("SignatureDetector",
            configuredIps(),
            configuredPorts(),
            configuredPayloadPatterns()
        );
    }

    private static Set<String> configuredIps() {
        String configured = ConfigManager.getInstance().getString("detection.signature.badIps",
                "198.51.100.4,203.0.113.5,192.0.2.1");
        Set<String> result = new HashSet<>();
        for (String ip : configured.split(",")) {
            if (!ip.isBlank()) result.add(ip.trim());
        }
        return result;
    }

    private static Set<Integer> configuredPorts() {
        String configured = ConfigManager.getInstance().getString("detection.signature.badPorts", "31337,4444,6667");
        Set<Integer> result = new HashSet<>();
        try {
            for (String port : configured.split(",")) {
                if (!port.isBlank()) result.add(Integer.parseInt(port.trim()));
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid detection.signature.badPorts configuration", e);
        }
        return result;
    }

    private static List<Pattern> configuredPayloadPatterns() {
        String configured = ConfigManager.getInstance().getString("detection.signature.payloadPatterns",
                ".*(DOS_FLOOD|EXPLOIT|MALWARE|ATTACK).*");
        List<Pattern> result = new ArrayList<>();
        for (String expression : configured.split(",")) {
            if (!expression.isBlank()) result.add(Pattern.compile(expression.trim(), Pattern.CASE_INSENSITIVE));
        }
        return result;
    }

    @Override
    public Optional<Alert> analyze(NetworkEvent e) {
        if (e == null) {
            return Optional.empty();
        }

        boolean ipMatch = badIps.contains(e.sourceIp());
        boolean portMatch = badPorts.contains(e.port());
        boolean payloadMatch = false;

        String payload = e.payload();
        if (payload != null && !payload.isEmpty()) {
            for (Pattern pattern : payloadPatterns) {
                if (pattern.matcher(payload).find()) {
                    payloadMatch = true;
                    break;
                }
            }
        }

        if (ipMatch || portMatch || payloadMatch) {
            AttackType attackType = AttackType.DOS_FLOOD;
            if (payload != null && payload.toUpperCase().contains("PORT_SCAN")) {
                attackType = AttackType.PORT_SCAN;
            } else if (payload != null && payload.toUpperCase().contains("DATA")) {
                attackType = AttackType.DATA_TRANSFER;
            } else if (payload != null && payload.toUpperCase().contains("LOGIN")) {
                attackType = AttackType.BRUTE_FORCE;
            }

            String desc = "Signature match: " +
                    (ipMatch ? "bad IP " + e.sourceIp() + " " : "") +
                    (portMatch ? "bad port " + e.port() + " " : "") +
                    (payloadMatch ? "matched payload pattern" : "");

            Alert alert = alertFactory.create(
                Severity.HIGH,
                attackType,
                e.sourceIp(),
                e.destIp(),
                getName(),
                desc.trim(),
                e.timestamp()
            );
            return Optional.of(alert);
        }

        return Optional.empty();
    }

    @Override
    public void reset() {
        // Stateless rule matching; satisfies reset() contract
    }

    public Set<String> getBadIps() {
        return Collections.unmodifiableSet(badIps);
    }

    public Set<Integer> getBadPorts() {
        return Collections.unmodifiableSet(badPorts);
    }

    public List<Pattern> getPayloadPatterns() {
        return Collections.unmodifiableList(payloadPatterns);
    }
}

