# Step 0 audit: what the completion prompt asks for against what exists

Date: 2026-11-08. Scope: the 74 numbered items in phases 1 to 13 of
`COMPLETION PROMPT: everything still missing in the Network Threat Detection project`.

Method: every item was checked against the code first, as Step 0 requires. A row is
`EXISTS` only when the code path is present and wired, `PARTIAL` when part of the
requirement is present, and `MISSING` when a search for the decisive identifier, endpoint
or config key found nothing. Evidence cites the file and the line that decides the row.

## Orientation (Step 0.1) and baseline (Step 0.3)

| Step | Result |
| --- | --- |
| `AGENTS.md` | does not exist; the rules live in this prompt and in `docs/change-log.md` |
| `README.md` | 21 sections, from `Build and run` to `Docker` |
| `docs/class-spec.md` | 106 elements, the five-pattern table at line 38 |
| `docs/web-spec.md` | present, describes the portal routes and the palette rules |
| `docs/qa-report.md` | Part A (2026-11-07) and Part B (2026-11-08), gate passed for the earlier plan |
| `docs/change-log.md` | phases 0 to 15 plus the cleanup entry |
| `config.properties` | 205 keys, every one listed with its default in `docs/configuration.md` |
| Java suite | `mvn -o -B test`: **259 tests, 0 failures, 46 classes** |
| Web suite | `npm test -- --run`: **66 tests, 15 files** |

## Step 0.2 is blocked by the owner

Version control is still absent. `git status` fails in both the project directory and the
workspace root, and there is no `.gitignore` at the workspace root. The owner has said the
repository is handled afterwards, so no `git init`, no branch and no commit was created
here. Every phase below is therefore recorded in `docs/change-log.md` instead of a commit
id.

If the owner does initialise, the root ignore list needs `.qoder/`, `threat-detection/.tools/`,
`target/`, `node_modules/`, `data/`, `evidence/` and `*.db`, because
`threat-detection/.gitignore` resolves its paths relative to itself.

## The 74 items

| Item | Requirement | Status | Evidence || --- | --- | --- | --- |
| 1.1 | Repository interfaces in `persistence`, in-memory default | EXISTS | `RecordStore`, `AlertRepository` and `FlowRepository` are interfaces; `InMemoryRecordStore`, `InMemoryAlertRepository` and `InMemoryFlowRepository` implement them, and `PersistenceService:71` falls back to `Stores.memory()` whenever no file opens |
| 1.2 | Also persist incidents, containment, audit, notifications, manifests, ML summary | EXISTS | `Database.applyV2` creates `incidents`, `containment_actions`, `audit_entries`, `notifications`, `evidence_manifests` and `ml_model` on top of flows and alerts; `Stores.sqlite` wires one repository per table and `PersistenceService` records through each |
| 1.3 | Restore stored state on startup | EXISTS | `IncidentResponseFacade.restore()` (line 277) reads alerts, incidents, unexpired blocks, the audit trail and the last model summary before the server listens and reports what came back; `RestoreTest` writes through one store, opens a new facade on the same file and asserts every count |
| 1.4 | `schema_version` plus a v1 to v2 migration with a test | EXISTS | `Database.SCHEMA_VERSION = 2`; `migrate()` applies V1, then V2, then writes `user_version`. `PersistenceTest.schemaVersionOneMigratesInPlace` builds a v1 file, opens it, and asserts the version, the kept flow row and the new fold columns |
| 1.5 | Corrupt database: store off, one error, no crash | EXISTS | `PersistenceService:63` logs one `Durable store unavailable` error and degrades to memory; `PersistenceTest.corruptDatabaseDegradesToMemory` writes a non-SQLite file and asserts a closed store, one report and no leaked handle (the `Database` constructor closes both connections when an open fails) |
| 1.6 | Retention sweeper covers every persisted table | EXISTS | `PersistenceService.sweepNow` deletes past the cutoff from all eight stores: flows, alerts, incidents, containment, audit, notifications, manifests and the model summary |
| 2.1 | `docs/security.md` | EXISTS | 300 lines: deployment modes, roles, password policy, sessions and re-entry, throttling, headers, audit rules, secrets, container hardening, dependency review, limitations |
| 2.2 | `app.demoMode`, banner, refusal to start without credentials | EXISTS | `security/SecurityPolicy.banner/startupProblems`; `Main` prints the banner and exits 2 on any problem; `GET /api/demo` plus `components/DemoBanner.tsx` on the sign-in page and in the shell |
| 2.3 | Password policy outside demo mode | EXISTS | `SecurityPolicy.passwordProblem` enforces `auth.password.minLength` (floor 8), not the username, not a demo password, letter and digit; credentials come from `NTD_*_PASSWORD` first, the file second |
| 2.4 | `auth.reauth.enabled` re-authentication for sensitive actions | EXISTS | shared `reauthStatus` gate on containment mode, notification control and retention: 401 on a wrong password, 429 with `Retry-After`, `reauthAt` freshness stamp, both outcomes audited |
| 2.5 | Idle and absolute session timeout, logout invalidation, rotation | EXISTS | `auth.session.timeoutSeconds` and `auth.session.absoluteTimeoutSeconds`; `expiredSession` invalidates and audits `auth.expired`; `logout` invalidates; `rotateSession` on sign in |
| 2.6 | Security headers, body limit, generic errors, HSTS behind TLS | EXISTS | `WebServer` sets CSP, `nosniff`, frame denial, referrer, permissions, COOP and CORP, optional HSTS; `tooLarge` answers 413 from `http.maxBodyBytes`; origin mismatch 403; one exception handler answers 500 without details |
| 2.7 | TLS reverse proxy example and Compose file | EXISTS | `deploy/Caddyfile` (tls internal, reverse_proxy, HSTS, -Server) and `docker-compose.yml` (ntd plus proxy, volumes, health gate); README Docker section documents both |
| 2.8 | Docker non-root and `HEALTHCHECK` | EXISTS | runtime stage adds user `ntd` uid 10001, `USER ntd`, `HEALTHCHECK` on `/healthz`, `JAVA_TOOL_OPTIONS` for the store, volumes for data and evidence |
| 2.9 | Audit persisted and append-only, entries for import and config reads, log injection stripped | EXISTS | `AuditLog.setRecorder` writes through to `audit_entries` as an insert and `restore` reloads it; `import.zeek` and `config.read` are recorded; `clean` flattens control characters and caps each field |
| 2.10 | Throttle per account and per IP, lockout expiry, no enumeration | EXISTS | `LoginThrottle` varargs check `account:<name>` and `address:<ip>`, each window expires on its own; blocked attempts answer 429 with `Retry-After`; wrong password and unknown user both answer 401 with an empty body |
| 2.11 | `mvn dependency:tree` and `npm audit` findings documented | EXISTS | `docs/security.md` lists the resolved tree from `target/dependency-tree.txt` (Javalin 6.3.0, Jetty 11.0.23, Jackson 2.17.2, sqlite-jdbc 3.46.1.3) and records `npm audit` at zero across 220 packages |
| 3.1 | `ImportService` replays flows through the live pipeline, instant and paced | EXISTS | `imports/ImportService.java` replays through `DetectionEngine.processNow`; pace is a clock multiplier with `import.replay.maxGapMillis` |
| 3.2 | Unknown hosts added as assets, reversible by reset | EXISTS | `addUnknownHosts` creates `import-<ip>` workstations up to `import.unknownHosts.max`; `reset()` removes exactly those ids |
| 3.3 | Label file joined for evaluation only | EXISTS | `imports/ImportLabels.java` parses `uid,label`; the service looks labels up after each event and never passes one to a detector |
| 3.4 | CLI `--replay-zeek`, `--labels`, `--speed` | EXISTS | `Main.replayZeek` prints the summary and the per-label table |
| 3.5 | `POST /api/import/zeek` and `GET /api/import/status` | EXISTS | both routes plus `GET /api/import/sample` are in `API_PATHS` and handled in `ApiRoutes` |
| 3.6 | Import page with drop zone, progress and per-label table | EXISTS | `pages/Import.tsx`: two drop zones, pace select, progress bar, stat tiles, per-label table |
| 3.7 | Sample traps stay silent, per-label assertion over the sample | EXISTS | `ImportServiceSampleTest` replays the bundled 1693-flow capture through the live facade with the replay profile (`config/replay.properties`): `NTP_HEALTH` raises no alert at any severity, `NORMAL_TYPO` and `NORMAL_BACKUP` raise no alert at HIGH or above, and `PORT_SCAN`, `BRUTE_FORCE`, `BEACONING`, `LATERAL_MOVEMENT`, `DATA_EXFIL` and `DOS_FLOOD` each raise at least one alert |
| 4.1 | JSON feed with type, value, category, confidence, expiry, about 50 entries | EXISTS | `src/main/resources/threat-intel.json` holds 50 entries (20 address, 15 domain, 15 sha256) with type, value, label, category, confidence and expires; `ThreatIntel.parse` reads the array, counts one expired row and keeps the other 49 live |
| 4.2 | Domain and hash matching on the payload, severity from category and confidence | EXISTS | `ThreatIntel.matchDomain`, `matchHash` and `matchPayload` are consulted by `ThreatIntelDetector`; `severityFor` reads the category table first and falls back to the confidence band; `IntelServiceTest` proves a subdomain hit, an uppercase digest hit and that the expired address never matches |
| 4.3 | `POST /api/intel/reload` and `GET /api/intel/status` | EXISTS | both routes are in `API_PATHS` and handled by `ApiRoutes.intelStatus` and `reloadIntel`; a reload is Admin only, needs password re-entry, is audited on both outcomes, and a failed read leaves the previous feed in place |
| 4.4 | Threat intel panel and an IoC match label | EXISTS | `Admin.tsx` `IntelPanel` (line 1041) shows entries, addresses, domains, digests, expired, skipped and the last reload, with a reload form; `Alerts.tsx:145` shows an `IoC` chip when the detector is `ThreatIntelDetector` |
| 4.5 | AttackLab scenario that contacts a blocklisted address | EXISTS | `AttackLab.tsx:21` offers `intel-contact` and explains that it reaches a listed address, domain and digest; `POST /api/scenarios` runs `ScenarioService.indicatorContact`, which sends 198.51.100.7, then `update.example.org`, then the packaged sha256 |
| 5.1 | Beaconing and lateral movement scenarios, `POST /api/scenarios`, presets | EXISTS | `ScenarioService` holds seven presets behind `POST /api/scenarios` (role gated, audited); `ScenarioServiceTest` proves 12 beacons about 30 s apart and six hosts on management ports; AttackLab lists the same presets |
| 5.2 | `detection.allowlist.*` for beaconing and exfiltration | EXISTS | `detection.beaconing.allowlist` and `detection.exfil.allowlist` are in `config.properties`; both detectors read them and test each address through the shared `Detector.listed`, which accepts a plain address or a CIDR |
| 5.3 | Detector naming mapping documented | EXISTS | README section `Detector names and the type each reports` maps all ten names (`SignatureDetector` to `SiemCorrelator`) to the closed four-value `AttackType` and names the factory or subscriber that wires each one |
| 6.1 | Folded repeats with `occurrences`, `firstSeen`, `lastSeen` and "x23" in the UI | EXISTS | `Alert.fold`, `AlertGate.Decision`, `AlertUpdateListener`, 13 columns in `TableSpecs.ALERT`, `foldLabel` in `web-client/src/alerts.ts` |
| 6.2 | Alert status transitions and `POST /api/alerts/{id}/status` | EXISTS | `domain/AlertStatus` move table, route in `ApiRoutes:141`, `AlertRegistry` lookup, 403/404/409 answers, audited `alert.status` |
| 6.3 | Suppression rules from JSON and the API, auditable, with a UI list | EXISTS | `detection/SuppressionRules`, `GET\|POST /api/suppression/rules`, `DELETE /api/suppression/rules/{id}`, Admin page panel, audited add and remove |
| 6.4 | Storm limiter `alerts.maxPerMinute` with a counter | EXISTS | `AlertQualityGate.overStormCap`, sliding minute over alert timestamps, `stormSuppressed` reported |
| 6.5 | FALSE_POSITIVE proposes a rule and is audited | EXISTS | `ApiRoutes.proposedRule` returned from the status route, `alert.status` and `alert.suppress.add` audit entries, rule created only by the second POST |
| 6.6 | Alert quality reports raw, delivered, ratio, suppressed, storm; shown on Overview | EXISTS | `/api/alert-quality` returns 15 fields including `raw`, `delivered`, `ratio`, `folded`, `stormSuppressed`; Overview renders `.quality-strip` from a 5 s poll |
| 6.7 | Benchmark outlier fixed or explained in `docs/benchmarks.md` | EXISTS | `docs/benchmarks.md` section `What the measurements found` narrates the gate outlier (105.71 us/op against 0.80 us for four detectors), its cause (`prune` walking the whole fold map) and the fix to 2.96 us; qa-report B.1 quotes the current table |
| 7.1 | Data-driven kill-chain rules with ordered stages and a Critical escalation | EXISTS | `KillChainRules` reads `config/kill-chain.json` with a built-in two stage fallback; `SiemCorrelator.advanceChains` walks one stage forward per alert per source and publishes `Possible compromise: ...` at the chain severity. Verified live: `chainsMatched` 1, `lastChain` named, broken rule reported through `chainProblem` |
| 7.2 | Incident timeline and `GET /api/incidents/{id}` | EXISTS | `ApiRoutes.incidentDetail` answers one incident with a derived timeline of `alert` and `escalation` entries; unknown id answers 404. Verified live |
| 7.3 | Searchable events with filters and paging on `/api/events` and `/api/alerts` | EXISTS | `/api/events` takes `q` (alias `text`), severity, attackType, detector, source, target, simulated, from, to, limit, offset and returns `{total, offset, limit, events}`; `/api/alerts` takes the same filters and stays an array. Malformed filters answer 400. Verified live |
| 7.4 | Events page with live tail and an incident timeline view | EXISTS | `Events.tsx` searches, tails every 3 s, pages and shows the selected row; `Incidents.tsx` renders the server timeline with a separate Focus host action |
| 8.1 | Containment mode set to off, ids or ips, plus `containment.minSeverity` | EXISTS | `ContainmentService.Mode` reads `containment.mode` and falls back to the `containment.enabled` and `containment.enforce` pair when it is absent, so old configurations keep their behaviour; `containment.minSeverity` and `containment.autoSeverity` form the automatic threshold, and `setMode` switches at runtime. Verified live |
| 8.2 | Asset-level containment overlay, Contained badge, release list | EXISTS | `GET /api/network` carries `contained` as `{ip, expiresAt, automatic}`; the store keeps `containedIps`, the Hosts table and the host panel render a Contained badge, and both the 3D scene and the flat map draw a dashed containment ring. The release list stays on Admin |
| 8.3 | Containment allowlist, rate limit, partition check through `BackbonePlanner` | EXISTS | `ContainmentSafeguards` refuses an allowlisted address, a burst above `containment.maxPerMinute`, and a block whose removal disconnects the topology after re-planning the backbone without that host; each refusal is counted and reported. Allowlist and rate limit verified live (409 with the reason) |
| 8.4 | Automatic containment creates a `MitigationTask` | EXISTS | `containmentTasks()` adds `contain-<assetId>` for every active automatic block in both planning paths, with the asset value and type cost, so the decay, reachability and capacity filters apply unchanged |
| 8.5 | IDS/IPS toggle in Control, re-auth, audit, contained sources stop at admission | EXISTS | The Control page posts the chosen mode with the account password; `POST /api/containment/mode` re-authenticates through `verifyPassword`, audits ALLOWED or DENIED, and `admit()` drops a contained source only in IPS mode. Verified live: 16 events dropped and 0 alerts from the blocked source, then 1 alert after release |
| 8.6 | Release is explicit and audited, expiry still works | EXISTS | `POST /api/containment/release`, audit entry, expiry; exercised in the browser pass |
| 9.1 | Alerted flows excluded from training | EXISTS | `MlFlowScorer.rememberAlertedPair` subscribes to the alert bus as an `AlertListener`, records the `src|dst` pair and drops any flow that matches a pair seen inside `ml.train.exclusionSeconds`; `Status.excluded()` counts the drops and `ml.train.maxPairs` bounds the table. Live run: 554 of 1693 imported flows excluded |
| 9.2 | Evaluation service: rates, precision, recall, F1, sweep, split by run | EXISTS | `ml/EvaluationService.java` retains labelled flows per run (bounded by `ml.eval.maxRuns` and `ml.eval.maxSamplesPerRun`), and reports `Point` with tp, fp, fn, tn, precision, recall, F1, false positive rate and accuracy, a sweep over `ml.eval.sweepStart/End/Step`, and one `RunReport` per run |
| 9.3 | `sim.noise.*` and unseen variants | EXISTS | `simulation/SimulationNoise` adds benign spikes, retries and uncommon ports and reshapes a share of attacks (scan offset, RDP brute force, flood on 443) under the same four `AttackType` values; `TrafficSimulator` applies it, `sim.noise.*` holds eleven keys, all defaulted off |
| 9.4 | Rules against model on the same labeled sets | EXISTS | `EvaluationService.rules(rows)` scores the `ruleAlerted` flag captured at replay time over the same rows; `Report.rules()` and `RunReport.rules()` carry it. Live run: rules reach F1 0.03 (8 tp, 128 fp, 401 fn) where the model reaches 0.80 |
| 9.5 | `/api/ml/evaluation`, `POST /api/ml/evaluate`, tables in Admin | EXISTS | `ApiRoutes.mlEvaluation` and `evaluateModel` (Admin only, `ml.evaluate` audited on both outcomes); `api.ts` adds the dataset and report types, `Admin.tsx` renders the chosen and best point, the sweep, the per-run table and the rule comparison, and the simulation noise panel |
| 9.6 | README states the data is simulated | EXISTS | `README.md` section `Flow anomaly model` now carries `Evaluation against labels`, `Limitations` (the data is simulated, the training set is the scoring set, exclusion depends on the rules) and `Simulation noise` |
| 10.1 | Console and email channels, secrets only from the environment | EXISTS | console line in `NotificationService.onAlert`, `notify/SmtpMailer` for email; `NTD_SMTP_USER`, `NTD_SMTP_PASSWORD` and `NTD_WEBHOOK_SECRET` come from the environment only |
| 10.2 | Retries with backoff, circuit breaker, per-hour rate, cooldown, audited attempts | EXISTS | `notifications.retries/backoffMillis/breakerThreshold/breakerCooldownSeconds/maxPerHour/cooldownSeconds`; attempts reported through `Recorder` as `notification.<channel>` |
| 10.3 | Notify on delivered alerts and escalations only, redaction, size limit | EXISTS | the gate runs before the bus fan-out, escalation alerts carry a flag, `notifications.redact` masks credential-shaped text and `maxBodyBytes` truncates |
| 10.4 | https only, SSRF rejection after DNS, no redirects to blocked targets | EXISTS | `notify/WebhookGuard.check` resolves the host and refuses non-public addresses; the client is built with `HttpClient.Redirect.NEVER` |
| 10.5 | `POST /api/notifications/test`, control and delivery history | EXISTS | `notificationTest` and `notificationControl` routes (Admin, password re-entry); `Delivery` history in `GET /api/notifications` |
| 11.1 | `/api/export/{kind}` for alerts, events, incidents and flows in csv and json, escaping, formula neutralisation, integrity hash | EXISTS | `ApiRoutes.exportTable` serves all four kinds through `export/ExportService`; csv quoting and `neutralise()` block formulas, `X-Content-SHA256` carries the body digest, `export.maxRows` caps rows |
| 11.2 | `GET /api/incidents/{id}/bundle` with a manifest hash | EXISTS | `ApiRoutes.incidentBundle` returns the detail plus a manifest (kind, formatVersion, createdAt, count, sha256) and repeats it in `X-Manifest-SHA256`; verified by recomputing the digest from the detail |
| 11.3 | Compliance control mapping with pass or fail text, labelled indicative | EXISTS | `ComplianceService.controls()` maps seven Annex A controls to PASS/PARTIAL/FAIL with evidence; every row carries `indicative` and the response repeats `MAPPING_NOTE` |
| 11.4 | Retention editable by Admin, validated, audited, purge covers all tables | EXISTS | `POST /api/retention` (Admin, password re-entry) validates 5..525600 minutes, audits `retention.update` with the previous value, sweeps on demand; `sweepNow` now also purges `ml_model` |
| 11.5 | Export buttons in Reports and Events, retention panel in Admin | EXISTS | Reports has CSV and JSON links for four kinds, Events has two, Admin has the retention form and the control table; verified live with 54 checks |
| 12.1 | Warm-up discarded, 10000 events, 5 repetitions, mean, p50, p95, p99, throughput | EXISTS | `bench/Benchmarks` warms up at a tenth of the scale and discards it, then times every call over `bench.rounds` (5) rounds; `Result` carries operations, rounds, samples, mean, p50, p95, p99, max and ops/s, `DEFAULT_EVENTS = 10000` |
| 12.2 | `--benchmark --soak 600` | EXISTS | `Main` parses `--soak [seconds]` and runs the table then the soak; `bench/Soak` drives `DetectionEngine.processNow` at `bench.soak.eventsPerSecond` with queue-depth backpressure and reports both latency distributions; a 600 s run is recorded in `docs/benchmarks.md` |
| 12.3 | `docs/benchmarks.md` with hardware, commands and measured table | EXISTS | `docs/benchmarks.md`: machine table, four commands, the six-row per-operation table, the 600 s soak table, and what each row covers |
| 12.4 | Live metrics endpoint and operations table row | EXISTS | `GET /api/metrics` in `ApiRoutes.metrics` returns 26 counters behind a session gate; `Admin.tsx` shows them in the "Pipeline metrics" operations row; verified live with 22 checks |
| 12.5 | Outlier fixed or explained, old QA paragraph corrected | EXISTS | three defects found and fixed: `AlertQualityGate.prune` bounded to 16 entries per delivery (105.71 us to 2.96 us), `FlowRecorder` access-order eviction, `EventLog` file write moved off the detection thread; qa-report B.1 now quotes the current table and explains the old one |
| 13.1 | `docs/demo-script.md`, `config/demo.properties`, `--config`, checklist | REMOVED | withdrawn by the owner in the cleanup phase: the scripted demo and its profile were deleted, `--config` remains and merges a properties file over the packaged table |
| 13.2 | `--demo [--seed] [--trace]`, deterministic trace file | REMOVED | withdrawn by the owner in the cleanup phase: `Main` no longer parses `--demo` or `--trace`, and `demo/DemoRunner` was deleted with its package |
| 13.3 | Class spec refreshed: count, packages, pattern table | EXISTS | `class-spec.md` states the element count, lists exactly five patterns; the package list and the Detector note are current |
| 13.4 | README: features, full config table, limitations, pipeline prose | EXISTS | `docs/configuration.md` lists all 205 keys and the README `Configuration` section tables the ones that change behaviour; the pipeline is described in `How an event moves`, the page tour in `Guided tour`, the limits in `Limitations` |

## Counts

| Status | Items |
| --- | --- |
| EXISTS | 72 |
| PARTIAL | 0 |
| MISSING | 0 |
| REMOVED | 2 |

All 74 items were audited as of 2026-11-08, after phases 1 to 13. Two of them, 13.1 and
13.2, were withdrawn later the same day at the owner's request, so 72 exist and 2 are
gone on purpose. The original measurement, kept for comparison, was 2 existed, 20 were
partial and 52 were missing on the audit date. Two rows were already satisfied when the
audit was taken; the rest were closed by the phases below. Evidence cites the file and
symbol that decides each row, and rows 1.3, 1.4, 1.5 and 3.7 cite the tests that now
prove them.

## Gate result (2026-11-08)

The final gate ran against the packaged jar, not a development server:

| Check | Result |
| --- | --- |
| `mvn -o -B test` | 259 tests, 0 failures, 0 errors, 46 classes |
| `npm test -- --run` | 66 tests, 15 files, exit 0 |
| `npm run typecheck` | exit 0, no type errors |
| `npm run build` | exit 0, emitted to `src/main/resources/web/` |
| packaged jar on port 8097 | `Restored schema 2`, `/healthz` 200, every page and panel exercised in a browser |

`docs/qa-report.md` Part C records the browser pass row by row, the defect the gate found in
the store and the client gaps it closed. Temp artefacts from the pass were removed from
`target/`; `target/dependency-tree.txt` stays because `docs/security.md` cites it.

## What this changes about the plan

The earlier plan (phases 0 to 15 in the change log) delivered a working detector stack:
flows, a store for flows and alerts, a Zeek parser, a text threat feed, four NDR detectors,
a dedupe gate, a k-means scorer, a distinct-signal correlator, IP containment, a webhook
outbox, evidence export and a timing report. This prompt asks for a different and larger
system on top of that: replay and import, kill-chain rules, alert lifecycle, export
formats, evaluation, and an honest benchmark. The gap is roughly seven new service
packages, twelve new endpoints, two new pages, three new documents and a rewrite of the
benchmark and demo entry points.

Suggested build order, chosen so each step can be verified by the step after it:

1. Phase 1 foundations, because every later item stores something: repository interfaces,
   six more tables, restore on startup, a v2 migration.
2. Phase 3 import and replay, because it creates the labeled, reproducible input that
   phases 9, 12 and 13 need.
3. Phase 6 alert lifecycle and phase 7 kill chain and search, which share the alert model.
4. Phase 8 containment modes, phase 10 notifications and phase 11 export, which share the
   audit and the role gates.
5. Phase 2 security, phase 9 evaluation, phase 12 benchmarks and phase 13 documentation
   last, because each of them measures or describes the four groups above.

Per the owner's instruction, tests are written and run once at the end rather than per
phase. Compile checks (`mvn -q compile`, `tsc --noEmit`) run after each phase.
