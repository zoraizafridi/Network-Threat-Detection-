package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TopologyLoaderTest {

    @Test
    @DisplayName("loadSample: 15-25 nodes, all four asset types, connected, and contains cycles")
    void testLoadSampleSpecification() {
        Network network = TopologyLoader.loadSample();
        assertNotNull(network);

        Collection<NetworkAsset> assets = network.getAssets();
        int nodeCount = assets.size();

        // 1. Must contain 15 to 25 nodes
        assertTrue(nodeCount >= 15 && nodeCount <= 25,
            "Node count must be between 15 and 25 (was " + nodeCount + ")");

        // 2. All four asset types must be present
        Set<AssetType> presentTypes = EnumSet.noneOf(AssetType.class);
        for (NetworkAsset asset : assets) {
            presentTypes.add(asset.getType());
        }
        assertEquals(4, presentTypes.size(), "All four asset types must be present");
        assertTrue(presentTypes.contains(AssetType.SERVER));
        assertTrue(presentTypes.contains(AssetType.WORKSTATION));
        assertTrue(presentTypes.contains(AssetType.ROUTER));
        assertTrue(presentTypes.contains(AssetType.IOT_DEVICE));

        // 3. Must prove isConnected() is true
        assertTrue(network.isConnected(), "TopologyLoader.loadSample() network must be connected");

        // 4. Must contain cycles:
        // A connected graph with V vertices and E >= V edges mathematically must contain cycles.
        int edgeCount = network.getLinks().size();
        assertTrue(edgeCount >= nodeCount,
            "Edge count (" + edgeCount + ") must be >= node count (" + nodeCount + ") to ensure cycles");

        // Explicit cycle verification in the core router backbone:
        // rt-core-1 -> rt-core-2 -> rt-dist-1 -> rt-core-1
        NetworkAsset r1 = network.getAsset("rt-core-1");
        NetworkAsset r2 = network.getAsset("rt-core-2");
        NetworkAsset r3 = network.getAsset("rt-dist-1");

        assertNotNull(r1);
        assertNotNull(r2);
        assertNotNull(r3);

        assertTrue(network.getNeighbours(r1).contains(r2), "r1 must connect to r2");
        assertTrue(network.getNeighbours(r2).contains(r3), "r2 must connect to r3");
        assertTrue(network.getNeighbours(r3).contains(r1), "r3 must connect to r1, completing a cycle");
    }

    @Test
    @DisplayName("loadFromFile: Positive case with valid file parsing")
    void testLoadFromFileValid(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("topology.txt");
        String content = """
            # Sample topology configuration
            ASSET SERVER s1 "Main Server" 10.0.0.1 5
            ASSET ROUTER r1 "Core Router" 10.0.0.254 4
            ASSET,WORKSTATION,w1,Finance WS,10.0.0.20,3
            ASSET,IOT_DEVICE,i1,Motion Sensor,10.0.0.80,1

            LINK l1 s1 r1 1.5 1000.0
            LINK,l2,r1,w1,2.0,100.0
            LINK l3 w1 i1 3.0 50.0
            """;
        Files.writeString(file, content);

        Network network = TopologyLoader.loadFromFile(file.toString());
        assertNotNull(network);
        assertEquals(4, network.getAssets().size());
        assertEquals(3, network.getLinks().size());
        assertTrue(network.isConnected());

        assertEquals(AssetType.SERVER, network.getAsset("s1").getType());
        assertEquals("Main Server", network.getAsset("s1").getName());
        assertEquals(AssetType.WORKSTATION, network.getAsset("w1").getType());
    }

    @Test
    @DisplayName("loadFromFile: Negative cases for missing file and invalid path")
    void testLoadFromFileMissing(@TempDir Path tempDir) {
        assertThrows(IllegalArgumentException.class, () ->
            TopologyLoader.loadFromFile(tempDir.resolve("non_existent.txt").toString())
        );

        assertThrows(IllegalArgumentException.class, () -> TopologyLoader.loadFromFile(null));
        assertThrows(IllegalArgumentException.class, () -> TopologyLoader.loadFromFile("   "));

        assertThrows(IllegalArgumentException.class, () -> TopologyLoader.loadFromFile(tempDir.toString()));
    }

    @Test
    @DisplayName("loadFromFile: Malformed files throw clear IllegalArgumentException")
    void testLoadFromFileMalformed(@TempDir Path tempDir) throws IOException {
        Path emptyFile = tempDir.resolve("empty.txt");
        Files.writeString(emptyFile, "# only comments\n\n");
        assertThrows(IllegalArgumentException.class, () ->
            TopologyLoader.loadFromFile(emptyFile.toString())
        );

        Path badDirective = tempDir.resolve("bad_directive.txt");
        Files.writeString(badDirective, "NODE s1 10.0.0.1\n");
        assertThrows(IllegalArgumentException.class, () ->
            TopologyLoader.loadFromFile(badDirective.toString())
        );

        Path badType = tempDir.resolve("bad_type.txt");
        Files.writeString(badType, "ASSET QUANTUM s1 Name 10.0.0.1 5\n");
        assertThrows(IllegalArgumentException.class, () ->
            TopologyLoader.loadFromFile(badType.toString())
        );

        Path incompleteAsset = tempDir.resolve("incomplete_asset.txt");
        Files.writeString(incompleteAsset, "ASSET SERVER s1 Name\n");
        assertThrows(IllegalArgumentException.class, () ->
            TopologyLoader.loadFromFile(incompleteAsset.toString())
        );

        Path badCrit = tempDir.resolve("bad_crit.txt");
        Files.writeString(badCrit, "ASSET SERVER s1 Name 10.0.0.1 not_a_number\n");
        assertThrows(IllegalArgumentException.class, () ->
            TopologyLoader.loadFromFile(badCrit.toString())
        );

        Path missingEndpoint = tempDir.resolve("missing_endpoint.txt");
        Files.writeString(missingEndpoint, """
            ASSET SERVER s1 Server 10.0.0.1 3
            LINK l1 s1 unknown_asset 1.0 100.0
            """);
        assertThrows(IllegalArgumentException.class, () ->
            TopologyLoader.loadFromFile(missingEndpoint.toString())
        );

        Path badLinkCost = tempDir.resolve("bad_link_cost.txt");
        Files.writeString(badLinkCost, """
            ASSET SERVER s1 Server 10.0.0.1 3
            ASSET ROUTER r1 Router 10.0.0.2 3
            LINK l1 s1 r1 invalid_cost 100.0
            """);
        assertThrows(IllegalArgumentException.class, () ->
            TopologyLoader.loadFromFile(badLinkCost.toString())
        );
    }
}

