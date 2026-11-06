package pk.ooad.ntd.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UtilityServicesTest {
    private final ConfigManager config = ConfigManager.getInstance();

    @AfterEach
    void clearEventLog() {
        EventLog.getInstance().clear();
    }

    @Test
    void configLoadsNumbersStringsAndCommaSeparatedLists() throws IOException {
        Path file = Files.createTempFile("ntd-config", ".properties");
        try {
            Files.writeString(file, "count=17\nratio=2.75\nname=  core  \nitems=alpha, beta,,gamma\nempty=  \n");
            config.load(file.toString());
            assertEquals(17, config.getInt("count", 0));
            assertEquals(2.75, config.getDouble("ratio", 0.0));
            assertEquals("core", config.getString("name", "fallback"));
            assertEquals(List.of("alpha", "beta", "gamma"), config.getList("items"));
            assertEquals(List.of(), config.getList("empty"));
            assertEquals(9, config.getInt("missing", 9));
            assertEquals(3.5, config.getDouble("missingDouble", 3.5));
            assertEquals("fallback", config.getString("missingString", "fallback"));
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test
    void configReportsMissingFilesAndInvalidValuesClearly() throws IOException {
        assertTrue(assertThrows(InvalidConfigException.class,
                () -> config.load("missing-ntd-config.properties")).getMessage().contains("not found"));
        Path file = Files.createTempFile("ntd-invalid-config", ".properties");
        try {
            Files.writeString(file, "count=not-a-number\n");
            config.load(file.toString());
            assertTrue(assertThrows(InvalidConfigException.class,
                    () -> config.getInt("count", 0)).getMessage().contains("count"));
            assertThrows(InvalidConfigException.class, () -> config.getList(" "));
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test
    void eventLogStoresEntriesAndClearIsIdempotent() {
        EventLog log = EventLog.getInstance();
        assertEquals(log, EventLog.getInstance());
        log.clear();
        log.log(LogLevel.WARN, "Detection", "threshold exceeded");
        assertEquals(1, log.getEntries().size());
        assertTrue(log.getEntries().get(0).contains("[WARN] [Detection] threshold exceeded"));
        assertThrows(NullPointerException.class, () -> log.log(null, "x", "y"));
        log.clear();
        log.clear();
        assertTrue(log.getEntries().isEmpty());
        assertFalse(log.getEntries().contains("threshold exceeded"));
    }
}
