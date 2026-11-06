# Project rules for AI assistants

Network Threat Detection and Cyber Security Monitoring System.
Java 17, Maven, Javalin web API, React web client (web-client), JUnit 5. Base package: pk.ooad.ntd.

## Source of truth
- docs/web-spec.md defines the look and behaviour of the web client. Its banned list is a hard rule.
- docs/class-spec.md defines every class, attribute, operation and relationship.
- Use the EXACT class, method and field names from it. The UML diagrams in the report must match the code.
- Do not add classes, patterns or public methods that are not in the spec. Ask first.

## Packages and dependency rule
domain, simulation, detection, service, response, util, web
- domain imports nothing from other project packages and contains no web or UI code.
- simulation and detection depend only on domain and util.
- response depends only on domain.
- service depends on domain, detection, simulation, response, util.
- web depends only on service (IncidentResponseFacade and Incident), domain (read-only) and detection.AlertListener (interface only). Main may depend on any package.
- web and web-client contain no detection, risk, Kruskal or DP logic. The client only displays and sends commands.
- Exception: - web must import nothing from detection except the AlertListener interface.

## Design rules
- Patterns, only these five: Strategy (Detector), Observer (AlertBus/AlertListener),
  Factory (AssetFactory, AlertFactory, DetectorFactory), Singleton (ConfigManager, EventLog),
  Facade (IncidentResponseFacade).
- NetworkEvent is immutable and has NO "malicious" label. Detectors never see ground truth.
- No machine learning. Rules must be explainable.
- No magic numbers: every threshold comes from ConfigManager (config.properties).
- A relationship is a field OR an arrow in the spec, never both. Follow the spec's fields.

## Concurrency
- Simulator thread -> BlockingQueue -> detection thread -> AlertBus -> StreamBroadcaster -> SSE to browsers.
- Web handlers call the facade under one lock.
- A failing AlertListener must not break the others. Exceptions on the detection thread are caught and logged.

## Workflow
- Work one phase at a time (see Project Setup Guide, section 9).
- Write JUnit 5 tests with each class: positive, negative and edge cases.
- Run `mvn clean test` before every commit. Never commit target/.
- One git branch per feature, small commits.
- Use a seeded java.util.Random and an injectable java.time.Clock so tests are reproducible.
- Never use the em dash character (U+2014) in code, comments, UI text or docs.
- Never edit docs/class-spec.md or docs/web-spec.md. If the spec seems wrong, stop and tell me.
- Client work follows docs/web-spec.md. Run npm test and npm run build in web-client before every commit.