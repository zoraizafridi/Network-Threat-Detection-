package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NetworkEventTest {

    @Test
    @DisplayName("Positive case: Instantiation and accessor methods return correct values")
    void testInstantiationAndAccessors() {
        long id = 101L;
        Instant now = Instant.now();
        String src = "192.168.1.10";
        String dst = "192.168.1.1";
        int port = 443;
        long bytes = 2048L;
        EventType type = EventType.CONNECT;
        boolean success = true;
        String payload = "SYN";

        NetworkEvent event = new NetworkEvent(id, now, src, dst, port, bytes, type, success, payload);

        assertEquals(id, event.id());
        assertEquals(now, event.timestamp());
        assertEquals(src, event.sourceIp());
        assertEquals(dst, event.destIp());
        assertEquals(port, event.port());
        assertEquals(bytes, event.bytes());
        assertEquals(type, event.type());
        assertTrue(event.success());
        assertEquals(payload, event.payload());
    }

    @Test
    @DisplayName("Immutability specification: Class is a record and all fields are private and final")
    void testAllFieldsAreFinalAndPrivate() {
        assertTrue(NetworkEvent.class.isRecord(), "NetworkEvent must be a Java record for constructor-free immutability");

        Field[] fields = NetworkEvent.class.getDeclaredFields();
        assertTrue(fields.length > 0, "NetworkEvent must declare fields");

        for (Field field : fields) {
            int modifiers = field.getModifiers();
            assertTrue(Modifier.isPrivate(modifiers), "Field " + field.getName() + " must be private");
            assertTrue(Modifier.isFinal(modifiers), "Field " + field.getName() + " must be final");
        }

        Method[] methods = NetworkEvent.class.getDeclaredMethods();
        for (Method method : methods) {
            assertFalse(
                method.getName().startsWith("set"),
                "NetworkEvent must not expose setters: " + method.getName()
            );
        }
    }

    @Test
    @DisplayName("Specification compliance: Exactly specified fields exist and NO malicious field")
    void testExactFieldsAndNoMaliciousField() {
        Field[] fields = NetworkEvent.class.getDeclaredFields();
        Set<String> fieldNames = Arrays.stream(fields)
            .map(Field::getName)
            .collect(Collectors.toSet());

        Set<String> expectedFields = Set.of(
            "id",
            "timestamp",
            "sourceIp",
            "destIp",
            "port",
            "bytes",
            "type",
            "success",
            "payload",
            "simulated"
        );

        assertEquals(expectedFields, fieldNames, "Declared fields must match the spec exactly");

        for (String name : fieldNames) {
            assertFalse(
                name.toLowerCase().contains("malicious"),
                "NetworkEvent must not have any malicious field or label: " + name
            );
        }
    }

    @Test
    @DisplayName("Provenance: the simulated tag defaults to false and is never a malicious label")
    void testSimulatedProvenance() {
        NetworkEvent plain = new NetworkEvent(1L, Instant.EPOCH, "10.0.0.1", "10.0.0.2", 80, 8L,
            EventType.REQUEST, true, "hello");
        assertFalse(plain.simulated());

        NetworkEvent injected = new NetworkEvent(1L, Instant.EPOCH, "10.0.0.1", "10.0.0.2", 80, 8L,
            EventType.REQUEST, true, "hello", true);
        assertTrue(injected.simulated());
        assertNotEquals(plain, injected);
    }

    @Test
    @DisplayName("Value equality and hashCode contract")
    void testEqualsAndHashCode() {
        Instant now = Instant.parse("2026-11-05T12:00:00Z");
        NetworkEvent event1 = new NetworkEvent(1L, now, "10.0.0.1", "10.0.0.2", 80, 512L, EventType.REQUEST, true, "GET /");
        NetworkEvent event2 = new NetworkEvent(1L, now, "10.0.0.1", "10.0.0.2", 80, 512L, EventType.REQUEST, true, "GET /");

        assertEquals(event1, event2);
        assertEquals(event1.hashCode(), event2.hashCode());
        assertEquals(event1, event1);
        assertNotEquals(event1, null);
        assertNotEquals(event1, "other-type");

        assertNotEquals(event1, new NetworkEvent(2L, now, "10.0.0.1", "10.0.0.2", 80, 512L, EventType.REQUEST, true, "GET /"));
        assertNotEquals(event1, new NetworkEvent(1L, now.plusSeconds(1), "10.0.0.1", "10.0.0.2", 80, 512L, EventType.REQUEST, true, "GET /"));
        assertNotEquals(event1, new NetworkEvent(1L, now, "10.0.0.9", "10.0.0.2", 80, 512L, EventType.REQUEST, true, "GET /"));
        assertNotEquals(event1, new NetworkEvent(1L, now, "10.0.0.1", "10.0.0.9", 80, 512L, EventType.REQUEST, true, "GET /"));
        assertNotEquals(event1, new NetworkEvent(1L, now, "10.0.0.1", "10.0.0.2", 8080, 512L, EventType.REQUEST, true, "GET /"));
        assertNotEquals(event1, new NetworkEvent(1L, now, "10.0.0.1", "10.0.0.2", 80, 1024L, EventType.REQUEST, true, "GET /"));
        assertNotEquals(event1, new NetworkEvent(1L, now, "10.0.0.1", "10.0.0.2", 80, 512L, EventType.LOGIN_ATTEMPT, true, "GET /"));
        assertNotEquals(event1, new NetworkEvent(1L, now, "10.0.0.1", "10.0.0.2", 80, 512L, EventType.REQUEST, false, "GET /"));
        assertNotEquals(event1, new NetworkEvent(1L, now, "10.0.0.1", "10.0.0.2", 80, 512L, EventType.REQUEST, true, "POST /"));
    }

    @Test
    @DisplayName("Edge case: Null and empty payloads, boundary numeric values")
    void testEdgeCases() {
        Instant epoch = Instant.EPOCH;
        NetworkEvent nullPayloadEvent = new NetworkEvent(
            0L,
            epoch,
            "",
            "",
            0,
            0L,
            EventType.CONNECT,
            false,
            null
        );

        assertEquals(0L, nullPayloadEvent.id());
        assertEquals(epoch, nullPayloadEvent.timestamp());
        assertEquals("", nullPayloadEvent.sourceIp());
        assertEquals("", nullPayloadEvent.destIp());
        assertEquals(0, nullPayloadEvent.port());
        assertEquals(0L, nullPayloadEvent.bytes());
        assertEquals(EventType.CONNECT, nullPayloadEvent.type());
        assertFalse(nullPayloadEvent.success());
        assertNull(nullPayloadEvent.payload());

        NetworkEvent boundaryEvent = new NetworkEvent(
            Long.MAX_VALUE,
            Instant.MAX,
            "255.255.255.255",
            "255.255.255.255",
            65535,
            Long.MAX_VALUE,
            EventType.DATA_TRANSFER,
            true,
            ""
        );

        assertEquals(Long.MAX_VALUE, boundaryEvent.id());
        assertEquals(Instant.MAX, boundaryEvent.timestamp());
        assertEquals(65535, boundaryEvent.port());
        assertEquals(Long.MAX_VALUE, boundaryEvent.bytes());
        assertEquals("", boundaryEvent.payload());
    }

    @Test
    @DisplayName("toString representation is non-empty and contains key properties")
    void testToString() {
        NetworkEvent event = new NetworkEvent(
            42L,
            Instant.EPOCH,
            "1.2.3.4",
            "5.6.7.8",
            22,
            128L,
            EventType.LOGIN_ATTEMPT,
            false,
            "root"
        );
        String s = event.toString();
        assertNotNull(s);
        assertTrue(s.contains("42"));
        assertTrue(s.contains("1.2.3.4"));
        assertTrue(s.contains("5.6.7.8"));
        assertTrue(s.contains("22"));
    }
}
