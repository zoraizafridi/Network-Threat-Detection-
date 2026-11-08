package pk.ooad.ntd;

import pk.ooad.ntd.bench.Benchmarks;
import pk.ooad.ntd.bench.Soak;
import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.imports.ImportService;
import pk.ooad.ntd.persistence.PersistenceException;
import pk.ooad.ntd.security.SecurityPolicy;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.util.ConfigManager;
import pk.ooad.ntd.util.InvalidConfigException;
import pk.ooad.ntd.web.WebServer;
import pk.ooad.ntd.zeek.ZeekConnLogParser;
import pk.ooad.ntd.zeek.ZeekImportResult;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public class Main {
    private static final String VERSION = "1.0";

    public static void main(String[] args) {
        applyConfigProfile(args);
        boolean web = false;
        Integer port = null;
        Long seed = null;
        String importZeek = null;
        String replayZeek = null;
        String labels = null;
        double speed = 0.0;
        Integer benchmark = null;
        Integer soak = null;
        try {
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if (arg.equals("--config")) {
                    if (i + 1 >= args.length) {
                        usage();
                        return;
                    }
                    i++;
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
                } else if (arg.equals("--replay-zeek")) {
                    if (i + 1 >= args.length) {
                        usage();
                        return;
                    }
                    replayZeek = args[++i];
                } else if (arg.equals("--labels")) {
                    if (i + 1 >= args.length) {
                        usage();
                        return;
                    }
                    labels = args[++i];
                } else if (arg.equals("--speed")) {
                    if (i + 1 >= args.length) {
                        usage();
                        return;
                    }
                    speed = Double.parseDouble(args[++i]);
                    if (Double.isNaN(speed) || speed < 0) {
                        usage();
                        return;
                    }
                } else if (arg.equals("--benchmark")) {
                    benchmark = ConfigManager.getInstance().getInt("bench.events", Benchmarks.DEFAULT_EVENTS);
                    if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                        benchmark = Integer.parseInt(args[++i]);
                    }
                } else if (arg.equals("--soak")) {
                    soak = 60;
                    if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                        soak = Integer.parseInt(args[++i]);
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
        if (replayZeek != null) {
            replayZeek(replayZeek, labels, speed);
            return;
        }
        if (benchmark != null) {
            System.out.print(Benchmarks.report(Benchmarks.run(benchmark)));
            if (soak == null) {
                return;
            }
        }
        if (soak != null) {
            runSoak(soak);
            return;
        }
        if (web) {
            ConfigManager config = ConfigManager.getInstance();
            SecurityPolicy policy = SecurityPolicy.from(config);
            System.out.println(policy.banner(VERSION));
            List<String> problems = policy.startupProblems(config);
            if (!problems.isEmpty()) {
                System.out.println("Refusing to start because app.demoMode=false:");
                for (String problem : problems) {
                    System.out.println("  - " + problem);
                }
                System.out.println("Supply the credentials listed above, or start with app.demoMode=true for the demo.");
                System.exit(2);
                return;
            }
            for (String warning : policy.warnings(config)) {
                System.out.println("warning: " + warning);
            }
            int chosenPort = port == null ? 8080 : port;
            long chosenSeed = seed == null ? 42L : seed;
            IncidentResponseFacade facade = new IncidentResponseFacade(TopologyLoader.loadSample(), chosenSeed);
            System.out.println(facade.restore().summary());
            WebServer server = new WebServer(facade, chosenPort);
            server.start(chosenPort);
        } else {
            usage();
        }
    }

    private static void applyConfigProfile(String[] args) {
        String explicit = null;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--config") && i + 1 < args.length) {
                explicit = args[i + 1];
            }
        }
        if (explicit == null) {
            return;
        }
        try {
            int keys = ConfigManager.getInstance().overlay(explicit);
            System.out.println("Configuration profile: " + explicit + " (" + keys + " keys)");
        } catch (InvalidConfigException ex) {
            System.out.println(ex.getMessage());
            System.exit(2);
        }
    }

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

    private static void replayZeek(String connLog, String labels, double speed) {
        if (!Boolean.parseBoolean(ConfigManager.getInstance().getString("zeek.enabled", "true"))) {
            System.out.println("The importer is switched off; set zeek.enabled=true to use it");
            return;
        }
        IncidentResponseFacade facade = new IncidentResponseFacade(TopologyLoader.loadSample(), 0L);
        try {
            ImportService.Report report = facade.getImportService().replayFile(Path.of(connLog),
                    labels == null ? null : Path.of(labels), speed);
            System.out.println(report.summary());
            for (String problem : report.problems()) {
                System.out.println("  ! " + problem);
            }
            for (ImportService.LabelStat stat : report.labels()) {
                System.out.printf("  %-18s %6d flows %6d alerts%n", stat.label(), stat.flows(), stat.alerts());
            }
        } catch (IOException ex) {
            System.out.println("Replay failed: " + ex.getMessage());
        } finally {
            facade.shutdown();
        }
    }

    private static void runSoak(int seconds) {
        IncidentResponseFacade facade = new IncidentResponseFacade(TopologyLoader.loadSample(), 42L);
        try {
            System.out.println("Soak: " + Math.max(1, seconds) + " s against the live pipeline");
            System.out.println(Soak.run(facade, seconds).summary());
        } finally {
            facade.shutdown();
        }
    }

    private static void usage() {
        System.out.println("Usage: java -jar threat-detection.jar --web [--port N] [--seed N]"
                + " | --import-zeek <conn.log>"
                + " | --replay-zeek <conn.log> [--labels <csv>] [--speed N]"
                + " | --benchmark [events] [--soak seconds]");
        System.out.println("Every form also accepts --config <file>, a properties file layered over the packaged"
                + " configuration.");
        System.out.println("--benchmark runs 5 timed rounds per row after a discarded warm-up; it defaults to "
                + "bench.events (" + Benchmarks.DEFAULT_EVENTS + ") events and writes no traffic."
                + " --soak runs the live pipeline at bench.soak.eventsPerSecond for the given seconds (60 when omitted).");
        System.out.println("The web server refuses to start with the shipped credentials when app.demoMode=false."
                + " Supply NTD_ADMIN_PASSWORD, NTD_ANALYST_PASSWORD and NTD_VIEWER_PASSWORD, or replace the stored hashes.");
    }
}
