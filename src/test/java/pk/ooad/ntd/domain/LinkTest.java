package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LinkTest {

    @Test
    @DisplayName("Positive: Link creation, endpoints access, and operations")
    void testLinkOperations() {
        Server server = new Server("s1", "Server 1", "10.0.0.1", 3);
        Router router = new Router("r1", "Router 1", "10.0.0.254", 4);
        Link link = new Link("l1", server, router, 2.5, 1000.0);

        assertEquals("l1", link.getId());
        assertEquals(server, link.getSource());
        assertEquals(router, link.getTarget());
        assertEquals(2.5, link.getBaseCost());
        assertEquals(1000.0, link.getBandwidth());
        assertEquals(LinkStatus.NORMAL, link.getStatus());

        assertTrue(link.connects(server));
        assertTrue(link.connects(router));
        assertEquals(router, link.getOtherEnd(server));
        assertEquals(server, link.getOtherEnd(router));

        link.markCompromised();
        assertEquals(LinkStatus.COMPROMISED, link.getStatus());

        link.reset();
        assertEquals(LinkStatus.NORMAL, link.getStatus());
    }

    @Test
    @DisplayName("Negative: Self-loop links and unconnected assets throw exceptions")
    void testNegativeLinkCases() {
        Server s1 = new Server("s1", "Server 1", "10.0.0.1", 3);
        Server s2 = new Server("s2", "Server 2", "10.0.0.2", 3);
        Workstation outsider = new Workstation("w1", "Outsider", "10.0.0.100", 1);

        assertThrows(IllegalArgumentException.class, () ->
            new Link("l-self", s1, s1, 1.0, 100.0)
        );

        assertThrows(NullPointerException.class, () ->
            new Link(null, s1, s2, 1.0, 100.0)
        );
        assertThrows(NullPointerException.class, () ->
            new Link("l1", null, s2, 1.0, 100.0)
        );
        assertThrows(NullPointerException.class, () ->
            new Link("l1", s1, null, 1.0, 100.0)
        );

        Link link = new Link("l1", s1, s2, 1.0, 100.0);
        assertFalse(link.connects(outsider));
        assertFalse(link.connects(null));

        assertThrows(IllegalArgumentException.class, () -> link.getOtherEnd(outsider));
        assertThrows(IllegalArgumentException.class, () -> link.getOtherEnd(null));
    }

    @Test
    @DisplayName("Equals and hashCode based on link id")
    void testLinkEqualsAndHashCode() {
        Server s1 = new Server("s1", "Server 1", "10.0.0.1", 3);
        Server s2 = new Server("s2", "Server 2", "10.0.0.2", 3);
        Link l1 = new Link("link-1", s1, s2, 1.0, 100.0);
        Link l2 = new Link("link-1", s1, s2, 5.0, 50.0);
        Link l3 = new Link("link-2", s1, s2, 1.0, 100.0);

        assertEquals(l1, l2);
        assertEquals(l1.hashCode(), l2.hashCode());
        assertNotEquals(l1, l3);
        assertNotEquals(l1, null);
        assertNotNull(l1.toString());
    }
}

