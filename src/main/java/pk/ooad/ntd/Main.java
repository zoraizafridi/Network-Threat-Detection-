package pk.ooad.ntd;

import pk.ooad.ntd.bench.Benchmarks;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.persistence.PersistenceException;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.web.WebServer;
import pk.ooad.ntd.zeek.ZeekConnLogParser;
import pk.ooad.ntd.zeek.ZeekImportResult;

import java.nio.file.Path;

public class Main {
    public static void main(String[] args) {
        boolean headless = false;
        boolean web = false;
        Integer port = null;
        Long seed = null;
        String importZeek = null;
        Integer benchmark = null;
        try {
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if (arg.equals("--headless")) {
                    headless = true;
                } else if (arg.equals("--web")) {
                    web = true;
                } else if (arg.equals("--port")) {
                    if (i + 1 >= args.length) {
                        usage();
                        return;
                    }
                    port = Integer.parseInt(args[++i]);
                } else if (arg.equals("--seed")) {
                    if (i + 1 >= args.length) {
                        usage();
                        return;
                    }
                    seed = Long.parseLong(args[++i]);
                } else if (arg.equals("--import-zeek")) {
                    if (i + 1 >= args.length) {
                        usage();
                        return;
                    }
                    importZeek = args[++i];
                } else if (arg.equals("--benchmark")) {
                    benchmark = 1000;
                    if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                        benchmark = Integer.parseInt(args[++i]);
                    }
                }
            }
        } catch (NumberFormatException ex) {
            usage();
            return;
        }
        if (importZeek != null) {
            importZeek(importZeek);
            return;
        }
        if (benchmark != null) {
            System.out.print(Benchmarks.report(Benchmarks.run(Math.max(200, benchmark))));
            return;
        }
        if (web) {
            int chosenPort = port == null ? 8080 : port;
            long chosenSeed = seed == null ? 42L : seed;
            IncidentResponseFacade facade = new IncidentResponseFacade(TopologyLoader.loadSample(), chosenSeed);
            WebServer server = new WebServer(facade, chosenPort);
            server.start(chosenPort);
        } else if (headless) {
            System.out.println("Headless mode (to be built)");
        } else {
            usage();
        }
    }

    /**
     * Offline import: parse a Zeek conn log and store the flows. The facade is
     * built but never started, so nothing listens and no simulator runs.
     */
    private static void importZeek(String path) {
        if (!Boolean.parseBoolean(ConfigManager.getInstance().getString("zeek.enabled", "true"))) {
            System.out.println("The offline importer is switched off; set zeek.enabled=true to use it");
            return;
        }
        IncidentResponseFacade facade = new IncidentResponseFacade(TopologyLoader.loadSample(), 0L);
        try {
            ZeekImportResult result = new ZeekConnLogParser().parse(Path.of(path));
            int stored = facade.getPersistenceService().importFlows(result.records());
            System.out.println(result.summary());
            for (String problem : result.problems()) {
                System.out.println("  ! " + problem);
            }
            System.out.println("stored " + stored + " flows in "
                    + facade.getPersistenceService().settings().databasePath());
        } catch (PersistenceException ex) {
            System.out.println(ex.getMessage());
        } catch (Exception ex) {
            System.out.println("Import failed: " + ex.getMessage());
        } finally {
            facade.shutdown();
        }
    }

    private static void usage() {
        System.out.println("Usage: java -jar threat-detection.jar --web [--port N] [--seed N]"
                + " | --import-zeek <conn.log> | --benchmark [events] | --headless");
    }
}
