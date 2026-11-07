package pk.ooad.ntd.web;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.staticfiles.Location;
import org.eclipse.jetty.server.session.SessionHandler;
import pk.ooad.ntd.service.IncidentResponseFacade;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

public class WebServer {
    private Javalin app;
    private final IncidentResponseFacade facade;
    private final ReentrantLock lock;
    private final StreamBroadcaster broadcaster;
    private final ApiRoutes routes;
    private final int requestedPort;

    public WebServer(IncidentResponseFacade facade, int port) {
        this.facade = Objects.requireNonNull(facade, "facade must not be null");
        this.requestedPort = port;
        this.lock = new ReentrantLock();
        this.broadcaster = new StreamBroadcaster();
        this.routes = new ApiRoutes(facade, broadcaster, lock);
        facade.addAlertListener(broadcaster);
    }

    public void start(int port) {
        if (app != null) {
            return;
        }
        app = Javalin.create(config -> {
            config.showJavalinBanner = false;
            config.jetty.modifyServletContextHandler(handler -> handler.setSessionHandler(new SessionHandler()));
            if (classpathWebPresent()) {
                config.staticFiles.add(staticFiles -> {
                    staticFiles.hostedPath = "/";
                    staticFiles.directory = "/web";
                    staticFiles.location = Location.CLASSPATH;
                    staticFiles.headers = Map.of("Cache-Control", "no-store");
                });
                if (WebServer.class.getResource("/web/index.html") != null) {
                    config.spaRoot.addHandler("/", WebServer::fallbackToIndex);
                }
            }
        });
        routes.register(app);
        app.start(port);
    }

    public void stop() {
        if (app != null) {
            app.stop();
            app = null;
        }
        broadcaster.close();
    }

    public int port() {
        return app == null ? requestedPort : app.port();
    }

    private static boolean classpathWebPresent() {
        return WebServer.class.getResource("/web") != null
                || WebServer.class.getResource("/web/") != null
                || WebServer.class.getResource("/web/index.html") != null;
    }

    private static void fallbackToIndex(Context ctx) {
        if (ctx.path().startsWith("/api") || ctx.path().startsWith("/assets/")) {
            ctx.status(404);
            return;
        }
        try (InputStream input = WebServer.class.getResourceAsStream("/web/index.html")) {
            if (input == null) {
                ctx.status(404);
                return;
            }
            ctx.contentType("text/html; charset=utf-8");
            ctx.result(new String(input.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException ex) {
            ctx.status(404);
        }
    }
}
