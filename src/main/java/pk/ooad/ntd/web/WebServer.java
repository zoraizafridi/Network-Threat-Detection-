package pk.ooad.ntd.web;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HandlerType;
import io.javalin.http.staticfiles.Location;
import org.eclipse.jetty.http.HttpCookie;
import org.eclipse.jetty.server.session.SessionHandler;
import pk.ooad.ntd.service.IncidentResponseFacade;
import pk.ooad.ntd.util.ConfigManager;

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
        broadcaster.seed(facade.restoredAlerts());
        facade.addAlertListener(broadcaster);
        facade.addAlertUpdateListener(broadcaster);
    }

    public void start(int port) {
        if (app != null) {
            return;
        }
        ConfigManager config = ConfigManager.getInstance();
        boolean secureCookie = Boolean.parseBoolean(config.getString("auth.session.secureCookie", "false"));
        int timeoutSeconds = Math.max(60, config.getInt("auth.session.timeoutSeconds", 28800));
        int cookieMaxAge = config.getInt("auth.session.maxAgeSeconds", 0);
        boolean hsts = Boolean.parseBoolean(config.getString("auth.hsts.enabled", "false"));
        int hstsMaxAge = Math.max(0, config.getInt("auth.hsts.maxAgeSeconds", 31_536_000));
        long maxBodyBytes = Math.max(1024, config.getInt("http.maxBodyBytes", 8_388_608));
        app = Javalin.create(javalin -> {
            javalin.showJavalinBanner = false;
            javalin.jetty.modifyServletContextHandler(handler -> {
                SessionHandler sessionHandler = new SessionHandler();
                sessionHandler.setMaxInactiveInterval(timeoutSeconds);
                sessionHandler.getSessionCookieConfig().setHttpOnly(true);
                sessionHandler.getSessionCookieConfig().setSecure(secureCookie);
                if (cookieMaxAge > 0) {
                    sessionHandler.getSessionCookieConfig().setMaxAge(cookieMaxAge);
                }
                sessionHandler.setSameSite(HttpCookie.SameSite.LAX);
                handler.setSessionHandler(sessionHandler);
            });
            if (classpathWebPresent()) {
                javalin.staticFiles.add(staticFiles -> {
                    staticFiles.hostedPath = "/";
                    staticFiles.directory = "/web";
                    staticFiles.location = Location.CLASSPATH;
                    staticFiles.headers = Map.of("Cache-Control", "no-store");
                });
                if (WebServer.class.getResource("/web/index.html") != null) {
                    javalin.spaRoot.addHandler("/", WebServer::fallbackToIndex);
                }
            }
        });
        app.before(ctx -> {
            ctx.header("X-Content-Type-Options", "nosniff");
            ctx.header("X-Frame-Options", "DENY");
            ctx.header("Referrer-Policy", "strict-origin-when-cross-origin");
            ctx.header("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
            ctx.header("Cross-Origin-Opener-Policy", "same-origin");
            ctx.header("Cross-Origin-Resource-Policy", "same-origin");
            ctx.header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';");
            if (hsts) {
                ctx.header("Strict-Transport-Security", "max-age=" + hstsMaxAge + "; includeSubDomains");
            }
            if (tooLarge(ctx, maxBodyBytes)) {
                ctx.status(413).result("");
                ctx.skipRemainingHandlers();
                return;
            }

            String method = ctx.method().name();
            if (!method.equals("GET") && !method.equals("HEAD") && !method.equals("OPTIONS")) {
                String origin = ctx.header("Origin");
                if (origin != null && !origin.isBlank()) {
                    try {
                        java.net.URI originUri = java.net.URI.create(origin);
                        String originHost = originUri.getHost();
                        int originPort = originUri.getPort();
                        String reqHost = ctx.host();
                        String hostName = reqHost.contains(":") ? reqHost.substring(0, reqHost.indexOf(':')) : reqHost;
                        int hostPort = reqHost.contains(":") ? Integer.parseInt(reqHost.substring(reqHost.indexOf(':') + 1)) : 80;

                        boolean hostMatches = originHost != null && (originHost.equalsIgnoreCase(hostName)
                                || (originHost.equalsIgnoreCase("localhost") && hostName.equalsIgnoreCase("127.0.0.1"))
                                || (originHost.equalsIgnoreCase("127.0.0.1") && hostName.equalsIgnoreCase("localhost")));
                        boolean portMatches = originPort == -1 || originPort == hostPort || (originPort == 80 && hostPort == -1);

                        if (!hostMatches || !portMatches) {
                            ctx.status(403).result("");
                            ctx.skipRemainingHandlers();
                        }
                    } catch (Exception ex) {
                        ctx.status(403).result("");
                        ctx.skipRemainingHandlers();
                    }
                }
            }
        });
        app.get("/healthz", ctx -> {
            ctx.header("Cache-Control", "no-store");
            ctx.json(Map.of("status", "ok"));
        });
        app.exception(Exception.class, (exception, ctx) -> {
            pk.ooad.ntd.util.EventLog.getInstance().log(pk.ooad.ntd.util.LogLevel.ERROR,
                    "http", ctx.method().name() + " " + ctx.path() + " failed: " + exception);
            ctx.status(500).json(Map.of("error", "internal server error"));
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

    private static boolean tooLarge(Context ctx, long limit) {
        String declared = ctx.header("Content-Length");
        if (declared != null && !declared.isBlank()) {
            try {
                return Long.parseLong(declared.trim()) > limit;
            } catch (NumberFormatException ex) {
                return true;
            }
        }
        HandlerType method = ctx.method();
        if (method == HandlerType.GET || method == HandlerType.HEAD || method == HandlerType.OPTIONS) {
            return false;
        }
        String body = ctx.body();
        return body != null && body.length() > limit;
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
