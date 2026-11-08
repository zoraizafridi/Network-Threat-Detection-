package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NetworkTest {

    @Test
    @DisplayName("Positive: Graph construction, querying, neighbours, links, and compromise detection")
    void testNetworkBasicOperations() {
        Network network = new Network();
        Server server = new Server("s1", "Web Server", "10.0.0.1", 4);
        Router router = new Router("r1", "Core Router", "10.0.0.254", 5);
        Workstation ws = new Workstation("w1", "Admin PC", "10.0.0.10", 3);

        network.addAsset(server);
        network.addAsset(router);
        network.addAsset(ws);

        Link l1 = new Link("l1", server, router, 1.0, 1000.0);
        Link l2 = new Link("l2", router, ws, 2.0, 100.0);
        network.addLink(l1);
        network.addLink(l2);

        assertEquals(3, network.getAssets().size());
        assertEquals(2, network.getLinks().size());
        assertEquals(server, network.getAsset("s1"));
        assertEquals(router, network.findByIp("10.0.0.254"));

        List<NetworkAsset> routerNeighbours = network.getNeighbours(router);
        assertEquals(2, routerNeighbours.size());
        assertTrue(routerNeighbours.contains(server));
        assertTrue(routerNeighbours.contains(ws));

        List<Link> serverLinks = network.getLinksOf(server);
        assertEquals(1, serverLinks.size());
        assertEquals(l1, serverLinks.get(0));

        assertEquals(0, network.getCompromisedLinks().size());
        l1.markCompromised();
        List<Link> compromised = network.getCompromisedLinks();
        assertEquals(1, compromised.size());
        assertEquals(l1, compromised.get(0));

        assertTrue(network.isConnected());
    }

    @Test
    @DisplayName("Composition ownership: Removing an asset cleans up associated links")
    void testRemoveAssetCleansUpLinks() {
        Network network = new Network();
        Server s1 = new Server("s1", "Server 1", "10.0.0.1", 3);
        Server s2 = new Server("s2", "Server 2", "10.0.0.2", 3);
        Link link = new Link("l1", s1, s2, 1.0, 100.0);

        network.addAsset(s1);
        network.addAsset(s2);
        network.addLink(link);
        assertEquals(1, network.getLinks().size());

        boolean removed = network.removeAsset("s1");
        assertTrue(removed);
        assertNull(network.getAsset("s1"));
        assertEquals(0, network.getLinks().size(), "Associated links must be removed when endpoint is removed");
        assertFalse(network.removeAsset("non-existent"));
        assertFalse(network.removeAsset(null));
    }

    @Test
    @DisplayName("Connectivity: Disconnected components return isConnected false, empty and single-node return true")
    void testConnectivityVariants() {
        Network empty = new Network();
        assertTrue(empty.isConnected(), "Empty network is trivially connected");

        Network single = new Network();
        single.addAsset(new Server("s1", "Single", "10.0.0.1", 1));
        assertTrue(single.isConnected(), "Single node network is connected");

        Network disconnected = new Network();
        Server a1 = new Server("a1", "A1", "10.0.0.1", 1);
        Server a2 = new Server("a2", "A2", "10.0.0.2", 1);
        disconnected.addAsset(a1);
        disconnected.addAsset(a2);
        assertFalse(disconnected.isConnected(), "Two isolated assets are disconnected");

        disconnected.addLink(new Link("l-a1-a2", a1, a2, 1.0, 10.0));
        assertTrue(disconnected.isConnected(), "Network becomes connected after link added");
    }

    @Test
    @DisplayName("resetAll: Resets risk scores, statuses, and links across the entire network")
    void testResetAll() {
        Network network = new Network();
        Server server = new Server("s1", "Server", "10.0.0.1", 3);
        Router router = new Router("r1", "Router", "10.0.0.2", 4);
        Link link = new Link("l1", server, router, 1.0, 100.0);

        network.addAsset(server);
        network.addAsset(router);
        network.addLink(link);

        server.addRisk(50.0);
        server.setStatus(AssetStatus.COMPROMISED);
        router.addRisk(30.0);
        router.setStatus(AssetStatus.SUSPICIOUS);
        link.markCompromised();

        network.resetAll();

        assertEquals(0.0, server.getRiskScore());
        assertEquals(AssetStatus.NORMAL, server.getStatus());
        assertEquals(0.0, router.getRiskScore());
        assertEquals(AssetStatus.NORMAL, router.getStatus());
        assertEquals(LinkStatus.NORMAL, link.getStatus());
    }

    @Test
    @DisplayName("Negative and Edge: Duplicate IDs, endpoints outside network, null lookups")
    void testNegativeCases() {
        Network network = new Network();
        Server s1 = new Server("s1", "Server 1", "10.0.0.1", 3);
        Server s2 = new Server("s2", "Server 2", "10.0.0.2", 3);
        Server duplicateId = new Server("s1", "Duplicate", "10.0.0.99", 2);
        Server external = new Server("ext", "External", "10.0.0.88", 2);

        network.addAsset(s1);
        network.addAsset(s2);

        assertThrows(IllegalArgumentException.class, () -> network.addAsset(duplicateId));
        assertThrows(NullPointerException.class, () -> network.addAsset(null));

        Link validLink = new Link("l1", s1, s2, 1.0, 10.0);
        network.addLink(validLink);
        assertThrows(IllegalArgumentException.class, () -> network.addLink(new Link("l1", s1, s2, 2.0, 20.0)));
        assertThrows(IllegalArgumentException.class, () -> network.addLink(new Link("l2", s1, external, 1.0, 10.0)));
        assertThrows(NullPointerException.class, () -> network.addLink(null));

        assertNull(network.getAsset("missing"));
        assertNull(network.getAsset(null));
        assertNull(network.findByIp("99.99.99.99"));
        assertNull(network.findByIp(null));
        assertNull(network.findByIp(""));

        assertThrows(IllegalArgumentException.class, () -> network.getNeighbours(null));
        assertThrows(IllegalArgumentException.class, () -> network.getLinksOf(null));
    }
}
