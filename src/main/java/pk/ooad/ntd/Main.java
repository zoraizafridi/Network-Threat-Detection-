package pk.ooad.ntd;

import pk.ooad.ntd.domain.TopologyLoader;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.web.WebServer;

public class Main {
    public static void main(String[] args) {
        boolean headless = false;
        boolean web = false;
        Integer port = null;
        Long seed = null;
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
                }
            }
        } catch (NumberFormatException ex) {
            usage();
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

    private static void usage() {
        System.out.println("Usage: java -jar threat-detection.jar --web [--port N] [--seed N] | --headless");
    }
}
