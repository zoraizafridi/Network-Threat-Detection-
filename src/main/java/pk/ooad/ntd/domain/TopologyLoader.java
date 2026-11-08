package pk.ooad.ntd.domain;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TopologyLoader {

    public static Network loadSample() {
        Network network = new Network();
        AssetFactory factory = new AssetFactory();

        NetworkAsset r1 = factory.create(AssetType.ROUTER, "rt-core-1", "Core Router 1", "10.0.0.1", 5);
        NetworkAsset r2 = factory.create(AssetType.ROUTER, "rt-core-2", "Core Router 2", "10.0.0.2", 5);
        NetworkAsset r3 = factory.create(AssetType.ROUTER, "rt-dist-1", "Distribution Router 1", "10.0.0.3", 4);

        network.addAsset(r1);
        network.addAsset(r2);
        network.addAsset(r3);

        NetworkAsset s1 = factory.create(AssetType.SERVER, "srv-web-1", "Web Server 1", "10.0.1.10", 4);
        NetworkAsset s2 = factory.create(AssetType.SERVER, "srv-web-2", "Web Server 2", "10.0.1.11", 4);
        NetworkAsset s3 = factory.create(AssetType.SERVER, "srv-db-1", "Database Server 1", "10.0.1.20", 5);
        NetworkAsset s4 = factory.create(AssetType.SERVER, "srv-auth-1", "Auth Server 1", "10.0.1.30", 5);

        network.addAsset(s1);
        network.addAsset(s2);
        network.addAsset(s3);
        network.addAsset(s4);

        NetworkAsset w1 = factory.create(AssetType.WORKSTATION, "ws-ops-1", "Ops Workstation 1", "10.0.2.1", 3);
        NetworkAsset w2 = factory.create(AssetType.WORKSTATION, "ws-ops-2", "Ops Workstation 2", "10.0.2.2", 3);
        NetworkAsset w3 = factory.create(AssetType.WORKSTATION, "ws-fin-1", "Finance Workstation 1", "10.0.2.11", 3);
        NetworkAsset w4 = factory.create(AssetType.WORKSTATION, "ws-fin-2", "Finance Workstation 2", "10.0.2.12", 3);
        NetworkAsset w5 = factory.create(AssetType.WORKSTATION, "ws-sec-1", "Security Workstation 1", "10.0.2.50", 4);
        NetworkAsset w6 = factory.create(AssetType.WORKSTATION, "ws-dev-1", "Dev Workstation 1", "10.0.2.70", 2);

        network.addAsset(w1);
        network.addAsset(w2);
        network.addAsset(w3);
        network.addAsset(w4);
        network.addAsset(w5);
        network.addAsset(w6);

        NetworkAsset i1 = factory.create(AssetType.IOT_DEVICE, "iot-cam-1", "Building Camera 1", "10.0.3.1", 2);
        NetworkAsset i2 = factory.create(AssetType.IOT_DEVICE, "iot-cam-2", "Building Camera 2", "10.0.3.2", 2);
        NetworkAsset i3 = factory.create(AssetType.IOT_DEVICE, "iot-sensor-1", "Temperature Sensor 1", "10.0.3.10", 1);
        NetworkAsset i4 = factory.create(AssetType.IOT_DEVICE, "iot-sensor-2", "Humidity Sensor 1", "10.0.3.11", 1);
        NetworkAsset i5 = factory.create(AssetType.IOT_DEVICE, "iot-badge-1", "Door Badge Reader 1", "10.0.3.20", 3);

        network.addAsset(i1);
        network.addAsset(i2);
        network.addAsset(i3);
        network.addAsset(i4);
        network.addAsset(i5);

        network.addLink(new Link("link-r1-r2", r1, r2, 1.0, 1000.0));
        network.addLink(new Link("link-r2-r3", r2, r3, 1.0, 1000.0));
        network.addLink(new Link("link-r3-r1", r3, r1, 1.0, 1000.0));

        network.addLink(new Link("link-s1-r1", s1, r1, 2.0, 500.0));
        network.addLink(new Link("link-s1-r2", s1, r2, 2.0, 500.0));
        network.addLink(new Link("link-s2-r2", s2, r2, 2.0, 500.0));
        network.addLink(new Link("link-s2-s1", s2, s1, 1.5, 800.0));
        network.addLink(new Link("link-s3-r1", s3, r1, 2.0, 500.0));
        network.addLink(new Link("link-s4-r2", s4, r2, 2.0, 500.0));

        network.addLink(new Link("link-w1-r3", w1, r3, 3.0, 100.0));
        network.addLink(new Link("link-w2-r3", w2, r3, 3.0, 100.0));
        network.addLink(new Link("link-w1-w2", w1, w2, 2.0, 100.0));
        network.addLink(new Link("link-w3-r3", w3, r3, 3.0, 100.0));
        network.addLink(new Link("link-w4-r3", w4, r3, 3.0, 100.0));
        network.addLink(new Link("link-w5-r3", w5, r3, 2.5, 100.0));
        network.addLink(new Link("link-w6-r3", w6, r3, 3.0, 100.0));

        network.addLink(new Link("link-i1-r3", i1, r3, 4.0, 50.0));
        network.addLink(new Link("link-i2-r3", i2, r3, 4.0, 50.0));
        network.addLink(new Link("link-i3-r3", i3, r3, 4.0, 20.0));
        network.addLink(new Link("link-i4-r3", i4, r3, 4.0, 20.0));
        network.addLink(new Link("link-i5-r1", i5, r1, 4.0, 50.0));

        return network;
    }

    public static Network loadFromFile(String path) {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("Path must not be null or blank");
        }

        Path filePath = Path.of(path);
        if (!Files.exists(filePath)) {
            throw new IllegalArgumentException("Topology file does not exist: " + path);
        }
        if (Files.isDirectory(filePath)) {
            throw new IllegalArgumentException("Path is a directory, not a file: " + path);
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(filePath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unable to read topology file: " + path, e);
        }

        Network network = new Network();
        AssetFactory factory = new AssetFactory();
        int lineNum = 0;

        for (String rawLine : lines) {
            lineNum++;
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) {
                continue;
            }

            List<String> tokens = parseTokens(line);
            if (tokens.isEmpty()) {
                continue;
            }

            String directive = tokens.get(0).toUpperCase();
            switch (directive) {
                case "ASSET" -> {
                    if (tokens.size() < 6) {
                        throw new IllegalArgumentException(
                            "Malformed topology file at line " + lineNum + ": incomplete ASSET specification"
                        );
                    }
                    String typeStr = tokens.get(1);
                    AssetType type;
                    try {
                        type = AssetType.valueOf(typeStr.toUpperCase());
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException(
                            "Malformed topology file at line " + lineNum + ": unknown asset type '" + typeStr + "'", e
                        );
                    }
                    String id = tokens.get(2);
                    String name = tokens.get(3);
                    String ip = tokens.get(4);
                    int criticality;
                    try {
                        criticality = Integer.parseInt(tokens.get(5));
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException(
                            "Malformed topology file at line " + lineNum + ": invalid criticality '" + tokens.get(5) + "'", e
                        );
                    }
                    network.addAsset(factory.create(type, id, name, ip, criticality));
                }
                case "LINK" -> {
                    if (tokens.size() < 6) {
                        throw new IllegalArgumentException(
                            "Malformed topology file at line " + lineNum + ": incomplete LINK specification"
                        );
                    }
                    String id = tokens.get(1);
                    String sourceId = tokens.get(2);
                    String targetId = tokens.get(3);
                    NetworkAsset source = network.getAsset(sourceId);
                    NetworkAsset target = network.getAsset(targetId);
                    if (source == null || target == null) {
                        throw new IllegalArgumentException(
                            "Malformed topology file at line " + lineNum +
                            ": link endpoints must exist in network: " + sourceId + ", " + targetId
                        );
                    }
                    double baseCost;
                    double bandwidth;
                    try {
                        baseCost = Double.parseDouble(tokens.get(4));
                        bandwidth = Double.parseDouble(tokens.get(5));
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException(
                            "Malformed topology file at line " + lineNum + ": invalid cost or bandwidth", e
                        );
                    }
                    network.addLink(new Link(id, source, target, baseCost, bandwidth));
                }
                default -> throw new IllegalArgumentException(
                    "Malformed topology file at line " + lineNum + ": unknown directive '" + tokens.get(0) + "'"
                );
            }
        }

        if (network.getAssets().isEmpty()) {
            throw new IllegalArgumentException("Malformed topology file: no assets found in " + path);
        }

        return network;
    }

    private static List<String> parseTokens(String line) {
        List<String> tokens = new ArrayList<>();
        if (line.contains(",")) {
            for (String part : line.split(",")) {
                tokens.add(part.trim());
            }
            return tokens;
        }

        Matcher matcher = Pattern.compile("([^\"]\\S*|\".+?\")\\s*").matcher(line);
        while (matcher.find()) {
            String token = matcher.group(1);
            if (token.startsWith("\"") && token.endsWith("\"") && token.length() >= 2) {
                token = token.substring(1, token.length() - 1);
            }
            tokens.add(token);
        }
        return tokens;
    }
}
