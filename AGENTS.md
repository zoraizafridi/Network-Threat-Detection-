# Project rules for AI assistants

Network Threat Detection and Cyber Security Monitoring System.
Java 17, Maven, Swing GUI, JUnit 5. Base package: pk.ooad.ntd.

## Source of truth
- docs/ui-spec.md defines the look of every screen (Swing and web). Its banned list is a hard rule.
- docs/class-spec.md defines every class, attribute, operation and relationship.
- Use the EXACT class, method and field names from it. The UML diagrams in the report must match the code.
- Do not add classes, patterns or public methods that are not in the spec. Ask first.

## Packages and dependency rule
domain, simulation, detection, service, response, ui, util, web
- domain imports nothing from other project packages and never imports Swing.
- simulation and detection depend only on domain and util.
- response depends only on domain.
- service depends on domain, detection, simulation, response, util.
- ui and web depend only on service (IncidentResponseFacade) and domain (read-only).
- ui contains no detection or algorithm code.

## Design rules
- Patterns, only these five: Strategy (Detector), Observer (AlertBus/AlertListener),
  Factory (AssetFactory, AlertFactory, DetectorFactory), Singleton (ConfigManager, EventLog),
  Facade (IncidentResponseFacade).
- NetworkEvent is immutable and has NO "malicious" label. Detectors never see ground truth.
- No machine learning. Rules must be explainable.
- No magic numbers: every threshold comes from ConfigManager (config.properties).
- A relationship is a field OR an arrow in the spec, never both. Follow the spec's fields.

## Concurrency
- Simulator thread -> BlockingQueue -> detection thread -> AlertBus.
- Swing updates only via SwingUtilities.invokeLater. Kruskal and DP run in SwingWorker.
- A failing AlertListener must not break the others. Exceptions on the detection thread are caught and logged.

## Workflow
- Work one phase at a time (see Project Setup Guide, section 9).
- Write JUnit 5 tests with each class: positive, negative and edge cases.
- Run `mvn clean test` before every commit. Never commit target/.
- One git branch per feature, small commits.
- Use a seeded java.util.Random and an injectable java.time.Clock so tests are reproducible.
- Do not implement ReportGenerator, Incident or IncidentManager until the open issue at the top of docs/class-spec.md is resolved.
- Never use the em dash character (U+2014) in code, comments, UI text or docs.
