package pk.ooad.ntd.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pk.ooad.ntd.security.AuditLog.Entry;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditLogTest {

    @Test
    @DisplayName("A disabled log records nothing")
    void disabledLogIgnoresRecords() {
        AuditLog log = new AuditLog(false, 100);
        log.record("admin", "login", "session", AuditLog.Outcome.ALLOWED, "");
        assertFalse(log.isEnabled());
        assertEquals(0, log.size());
        assertEquals(0, log.recent(10).size());
    }

    @Test
    @DisplayName("The ring keeps the newest entries and drops the oldest")
    void ringKeepsNewest() {
        AuditLog log = new AuditLog(true, 3);
        for (int i = 1; i <= 5; i++) {
            log.record("admin", "action-" + i, "target", AuditLog.Outcome.ALLOWED, "detail " + i);
        }
        assertEquals(3, log.size());
        List<Entry> rows = log.recent(10);
        assertEquals(3, rows.size());
        assertEquals(5, rows.get(0).sequence(), "newest first");
        assertEquals(3, rows.get(2).sequence());
        assertEquals("action-5", rows.get(0).action());
    }

    @Test
    @DisplayName("Denied and failed outcomes are counted separately")
    void countersTrackOutcomes() {
        AuditLog log = new AuditLog(true, 10);
        log.record("admin", "a", "t", AuditLog.Outcome.ALLOWED, "");
        log.record("viewer", "b", "t", AuditLog.Outcome.DENIED, "");
        log.record("viewer", "c", "t", AuditLog.Outcome.DENIED, "");
        log.record("admin", "d", "t", AuditLog.Outcome.FAILED, "");
        assertEquals(4, log.size());
        assertEquals(2, log.deniedCount());
        assertEquals(1, log.failedCount());
    }

    @Test
    @DisplayName("A null actor is recorded as anonymous and nulls become empty strings")
    void nullsAreNormalised() {
        AuditLog log = new AuditLog(true, 10);
        log.record(null, "login", null, null, null);
        Entry entry = log.recent(1).get(0);
        assertEquals("anonymous", entry.actor());
        assertEquals("", entry.target());
        assertEquals("", entry.detail());
        assertEquals("ALLOWED", entry.outcome(), "a missing outcome is recorded as allowed");
        assertEquals(0, log.deniedCount());
        assertEquals(0, log.failedCount());
        assertEquals(0, entry.detail().length());
    }

    @Test
    @DisplayName("Blank actions are ignored and reset clears the ring and counters")
    void blankActionIgnoredAndReset() {
        AuditLog log = new AuditLog(true, 10);
        log.record("admin", "  ", "t", AuditLog.Outcome.DENIED, "");
        assertEquals(0, log.size());
        assertEquals(0, log.deniedCount());

        log.record("admin", "login", "t", AuditLog.Outcome.DENIED, "");
        log.reset();
        assertEquals(0, log.size());
        assertEquals(0, log.deniedCount());
        assertEquals(0, log.recent(5).size());
        log.record("admin", "after", "t", AuditLog.Outcome.ALLOWED, "");
        assertEquals(1, log.recent(1).get(0).sequence(), "the sequence restarts after reset");
        assertTrue(log.getMaxRecords() >= 1);
    }
}
