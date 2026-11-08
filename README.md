# Network Threat Detection & Cyber Security Monitoring System

Java 17 service with a React client. The server is the source of detection, risk, and planning.

## Build and run

### Quick start (Standard environment)

```bash
cd web-client
npm ci
npm test
npm run typecheck
npm run build
cd ..
mvn test
mvn package
java -jar target/threat-detection-1.0-SNAPSHOT.jar --web --port 8080 --seed 42
```

### Workspace local toolchain (.tools)

When no JDK, Maven or Node is installed globally, portable copies live in `.tools` (git ignored):

```cmd
# Run tests
.\.tools\run-mvn.cmd test
.\.tools\run-npm.cmd test -- --run
.\.tools\run-npm.cmd run typecheck

# Package the server (web assets are pre-built in src/main/resources/web)
.\.tools\run-mvn.cmd package -DskipTests

# Start the web portal
.\.tools\jdk\bin\java.exe -jar target\threat-detection-1.0-SNAPSHOT.jar --web --port 8080 --seed 42
```

The two wrappers put `.tools\jdk` and `.tools\node` on the path for one command, and Maven reads its local repository from `.tools\settings.xml`. Nothing outside the folder changes.

Open your browser at `http://localhost:8080/`. Log in with any of the built-in accounts:

| Username | Password | Role | Capabilities |
| --- | --- | --- | --- |
| `admin` | `admin` | Admin | Full control: attack injection, containment, retention, threat intel reload, model evaluation |
| `analyst` | `analyst` | Security Analyst | Mitigation planning, investigations, report exports, scenario launches |
| `viewer` | `viewer` | Viewer | Read-only monitoring of topology, flows, alerts and incidents |

Each password matches the username by default. For production deployments start with `-Dntd.app.demoMode=false` and set `NTD_ADMIN_PASSWORD`, `NTD_ANALYST_PASSWORD` and `NTD_VIEWER_PASSWORD`; the server refuses to start while an account still holds a shipped credential. `docs/security.md` covers the full posture.

### Execution modes and CLI switches

- **Web Portal Mode:**
  ```cmd
  java -jar target\threat-detection-1.0-SNAPSHOT.jar --web --port 8080 --seed 42
  ```
  `--web` starts the HTTP and SSE server. `--port` defaults to 8080 and `--seed` defaults to 42.

- **Offline Zeek Log Import:**
  ```cmd
  java "-Dntd.persistence.enabled=true" -jar target\threat-detection-1.0-SNAPSHOT.jar --import-zeek src/main/resources/samples/sample-conn.log
  ```
  Parses a Zeek `conn.log` offline and stores the connection records into SQLite.

- **Live Pipeline Replay (With detection profile):**
  ```cmd
  java -jar target\threat-detection-1.0-SNAPSHOT.jar --replay-zeek src/main/resources/samples/sample-conn.log --labels src/main/resources/samples/sample-conn.labels.csv --config config/replay.properties
  ```
  Pushes the capture through the live pipeline with beaconing, exfiltration, lateral movement and flood detectors enabled.

- **Performance Benchmarks and Sustained Soak Test:**
  ```cmd
  java -jar target\threat-detection-1.0-SNAPSHOT.jar --benchmark 10000 --soak 60
  ```
  `--benchmark [events]` runs five rounds over hot-path operations and prints percentiles; `--soak [seconds]` runs sustained load against the live pipeline. With no switch the program prints usage.

## How an event moves

Every feature below is a stage on one pipeline, and the stages are in this order.

1. Something offers an event: the simulator, an attack injection, a Zeek import or a replay. It enters
   the detection queue, and the queue depth is the backpressure signal.
2. The engine's admission check runs first. Containment installs it, so traffic from a blocked
   address is counted as dropped before any observer or detector sees it.
3. Registered observers run next: the flow recorder folds events into connection records and the
   history tap keeps a bounded window for the pages.
4. Nine detectors analyze the event independently, each returning at most one alert: five signature
   and threshold rules plus four behavioural ones (beaconing, exfiltration, lateral movement, flood).
5. A per source cooldown and the alert quality gate decide what is delivered. The gate drops what is
   below the severity floor or silenced by a rule, folds repeats of the same detector, attack type,
   source and target into the row already on screen, and caps deliveries per minute.
6. The alert bus fans the surviving alert out to every consumer: asset risk, incidents, the
   correlator, notifications, the durable store and the live stream. Consumers do not know about each
   other; each one listens to the same bus.
7. The correlator counts distinct attack types per source, walks the ordered kill chains from
   `config/kill-chain.json`, and publishes an escalation back onto the same bus, so an escalation
   reaches risk, incidents and the store without those classes knowing it exists.
8. The HTTP layer only reads that state, and containment only writes into the seams the pipeline
   already has: the admission predicate and the alert bus. `--benchmark` and `--soak` drive the same
   classes with a synthetic producer, each event processed on the calling thread.

## Configuration

`src/main/resources/config.properties` holds 205 keys and `docs/configuration.md` lists every one
with its default. The values that change what the system does are:

| Key | Default | Meaning |
| --- | --- | --- |
| `app.demoMode` | `true` | Demo accounts, each password equal to its username. Set to `false` for anything else. |
| `persistence.enabled` | `false` | Write flows, alerts, incidents and audit through to SQLite |
| `ml.enabled` | `false` | Train and score the flow anomaly model |
| `correlation.enabled` | `false` | Count distinct attack types per source and walk kill chains |
| `containment.mode` | `off` | `off`, `IDS` (record) or `IPS` (refuse traffic) |
| `containment.enforce` | `false` | Let a block actually drop events at admission |
| `containment.auto` | `false` | Let the system block without an operator |
| `detection.beaconing.enabled` | `false` | Behavioural detector, window suits a live sensor |
| `detection.exfil.enabled` | `false` | Behavioural detector, counts outbound bytes |
| `detection.lateral.enabled` | `false` | Behavioural detector, counts internal reach |
| `detection.flood.enabled` | `false` | Behavioural detector, counts connections to one destination |
| `notifications.enabled` | `false` | Console, mail and webhook delivery |
| `sim.noise.enabled` | `false` | Bend the simulator's traffic without adding an attack type |
| `alerts.minSeverity` | `LOW` | Alert quality gate floor |
| `alerts.maxPerMinute` | `600` | Delivery cap, on top of folding |
| `auth.session.timeoutSeconds` | `28800` | Idle session timeout |
| `audit.maxRecords` | `2000` | Bounded audit ring, mirrored to the store when it is on |

Every key can be changed for one run with `-Dntd.<key>=<value>` before `-jar`, or for a session
with `--config <file>`, which merges the file over the packaged table instead of replacing it, so a
profile only lists what it changes.

```
java -Dntd.ml.enabled=true -Dntd.persistence.enabled=true -jar target/threat-detection-1.0-SNAPSHOT.jar --web
```

## Flow telemetry

The flow recorder taps the detection engine's event stream and folds events that share a five
tuple into one connection record. Records close after the idle timeout, stay readable for the
retention window, and are served read only at `GET /api/flows` (filters: `src`, `dst`, `port`,
`from`, `to`, `limit`). The web client shows them on the Flows page, which polls while it is open.

| Key | Default | Meaning |
| --- | --- | --- |
| `flow.enabled` | `true` | Record flows at all |
| `flow.idleTimeoutSeconds` | `30` | Inactivity that closes a flow |
| `flow.maxRecords` | `2000` | Closed records kept in memory |
| `flow.maxActiveFlows` | `5000` | Open flows kept in memory |
| `flow.retentionMinutes` | `30` | Age at which a closed record is dropped |
| `flow.api.max` | `500` | Rows one `/api/flows` response may return |
| `flow.udpPorts` | `53,123,161,...` | Ports reported as UDP, everything else is TCP |
| `flow.labels` | `NAME=regex` list | Payload rules that name a flow, first match wins |

Two fields are honest projections rather than measurements. The simulator carries no source port,
so the recorder derives one deterministically from the tuple, and `bytesIn` stays zero because the
feed never reports reply traffic. Both are documented on `FlowRecord`.

Set `flow.enabled=false` to take the recorder out of the path; detection behaves exactly as before.

## Durable store

`persistence.enabled=true` keeps closed flows and raised alerts in a SQLite file (off by
default). Producers never wait on the disk: two bounded write-behind queues hand batches to one
daemon worker, and `flush` is a durability barrier rather than a queue-length check, so a caller
that flushes and then reads sees the rows it queued. A full queue refuses the newest row and
counts it, a batch the store rejects is counted and logged once per outage, and a database that
will not open degrades to bounded in-memory lists with a single error, so the detector keeps
running and the history endpoint keeps answering. This is the only package that touches SQL, and
nothing on the detection path blocks on it.

Eight tables, one column layout per table: `flows`, `alerts`, `incidents`, `containment_actions`,
`audit_entries`, `notifications`, `evidence_manifests` and `ml_model`. The schema carries a
`user_version`. Opening a file written by an older build migrates it in place (v1 to v2 adds the
six tables and the folded-alert columns) and keeps the rows it already had; opening a file written
by a newer build refuses to start instead of guessing. `GET /api/persistence/status` reports the
schema version next to the row counts, so the answer to "did the upgrade run" is one request away.

Repository reads and writes go through an interface with two implementations: the SQLite one, and
an in-memory one used when no file is open. Nothing above the package checks which is in use.

Restore on start reads back what outlives a restart and nothing else:

| Comes back | Does not come back |
| --- | --- |
| Alerts in the stream ring (`alerts.buffer.max`) | Flows that were still open |
| Incidents with the alerts whose rows survive | Model centroids and training state |
| Blocks that have not expired | Expired or released blocks |
| The audit trail (`audit.maxRecords`) | The current session, the response plan |
| The last model summary as a record of the previous run | Counters that describe this run |

`GET /api/persistence/status` reports stored rows, queued rows, dropped rows, written rows, the
schema version, the last flush and the last error. `GET /api/flows/history` serves kept flows
newest first. The Flows page has a Live and a Stored switch for the two sources.

| Key | Default | Meaning |
| --- | --- | --- |
| `persistence.enabled` | `false` | Open the durable store |
| `persistence.dir` | `data` | Directory holding the database file |
| `persistence.file` | `ntd.db` | File name |
| `persistence.queueCapacity` | `5000` | Rows one queue holds before it refuses |
| `persistence.batchSize` | `200` | Rows per committed transaction |
| `persistence.flushIntervalMillis` | `500` | Idle time before a partial batch is written |
| `persistence.retentionMinutes` | `1440` | Age at which a row is swept |
| `persistence.sweepMinutes` | `5` | How often the sweeper runs |
| `persistence.restore.incidents` | `200` | Incidents read back on start |

## Zeek import

`--import-zeek <conn.log>` parses an offline Zeek conn log, converts each row into the same
`FlowRecord` the live recorder produces, and stores it. The facade is built but never started, so
nothing listens and no simulator runs. The parser reads the `#fields` header instead of assuming a
column order, skips malformed rows, counts them, and caps the import at `zeek.import.maxFlows`. It
needs the durable store to be switched on, and it prints why when it is not.

`--replay-zeek <conn.log> [--labels <csv>] [--speed N]` goes further: it sends every connection
through the live pipeline, so the detectors see the capture exactly as they see simulator traffic.
Nothing is special-cased for replay. Each flow becomes one `NetworkEvent` at the connection's own
start time, and the event type follows the measurement:

| Conn log fact | Event |
| --- | --- |
| `orig_bytes` above zero | `DATA_TRANSFER` with those bytes |
| `orig_bytes` zero | `CONNECT` with zero bytes |
| `conn_state` in `import.failureStates` (`S0`, `REJ`, `RSTO`, `RSTR`) | `success=false` |
| anything else | `success=true` |

The payload is empty: a conn log carries no payload, and an empty payload tells a payload-matching
detector nothing instead of feeding it something invented. A refused connection is therefore a
failed `CONNECT`, not a failed login, so a capture with no login traffic cannot make the brute force
detector fire.

The replay is synchronous with the pipeline: one event is processed before the next is offered,
which is what lets the report say how many alerts each flow raised. `--speed` is a clock
multiplier. `0` replays as fast as the pipeline accepts (about half a second for the sample), `1`
keeps the recorded rhythm, and `60` runs a minute of capture per second. A single gap longer than
`import.replay.maxGapMillis` is compressed to it, so an overnight pause in a capture does not stall
a replay.

Addresses in the log that the topology does not know become workstation assets, so their alerts
land somewhere on the map. They are capped by `import.unknownHosts.max` and removed again by a
simulation reset. With the durable store on, the exporter rows are stored and the flow recorder is
paused for the replay, so the flow table holds one row per connection rather than two copies of it;
with the store off, the recorder builds the history from the replayed events instead.

A label file (`uid,label`, header optional) is joined after the run. Labels never reach a detector:
their only job is to say which labelled traffic produced which alerts.

```
java -jar target/threat-detection-1.0-SNAPSHOT.jar --replay-zeek src/main/resources/samples/sample-conn.log --labels src/main/resources/samples/sample-conn.labels.csv
```

On the sample with the default detector set that prints 1693 flows and about 140 alerts: the port
scan, the exfiltration transfers and the lateral chain raise alerts, and `NTP_HEALTH` stays silent
because thirty polls of one port from one address never look like a scan. Add `--config
config/replay.properties` to turn on the flood, beaconing, exfiltration and lateral detectors and
see alerts for all labelled attack types with the benign traps kept quiet.

The same replay is available in the portal under **Import**: drop a conn log and a label file, pick
a pace and watch the progress bar and the per-label table. `POST /api/import/zeek` starts a run and
returns its first status snapshot; `GET /api/import/status` reports progress and the last report;
`GET /api/import/sample` serves the bundled capture. Starting a replay needs the same role as
starting the simulator, and the audit trail records who started it and what it did.

A seeded sample ships with the code: `src/main/resources/samples/sample-conn.log` (1693
connections over 30 minutes, plus `sample-conn.labels.csv` with the ground truth label per uid).
It is regenerated by `tools/make_conn_log.py`.

```
java "-Dntd.persistence.enabled=true" -jar target/threat-detection-1.0-SNAPSHOT.jar --import-zeek src/main/resources/samples/sample-conn.log
```

The store is off by default, so the `ntd.` override is what turns it on for this one run. The
override is quoted because Windows PowerShell splits an unquoted `-D` argument that contains dots.

| Key | Default | Meaning |
| --- | --- | --- |
| `zeek.enabled` | `true` | Allow the offline importer and the replay |
| `zeek.import.maxFlows` | `50000` | Rows one import may parse |
| `import.replay.maxGapMillis` | `5000` | Longest single pause a paced replay will honour |
| `import.failureStates` | `S0,REJ,RSTO,RSTR` | Connection states that mean the attempt failed |
| `import.unknownHosts.max` | `500` | Assets one import may add to the topology |
| `import.unknownHosts.criticality` | `1` | Criticality given to an imported host |
| `import.request.maxBytes` | `8388608` | Largest log body the endpoint accepts |
| `import.cancelJoinMillis` | `2000` | How long a reset waits for a replay to stop |

## Threat intel

`intel.enabled=true` loads a plain text feed at `intel.feed` (lines of `address-or-cidr label
[LOW|HIGH|CRITICAL]`, `#` starts a comment). A match decides that an alert is raised; the event
type decides which attack bucket it lands in. Only IPv4 is matched, IPv6 lines are skipped and
counted, and a feed that will not load leaves the detector quiet with one error. The shipped
`threat-intel.txt` holds the RFC 5737 documentation ranges on purpose: enabling the feature out of
the box adds capability without adding alerts.

| Key | Default | Meaning |
| --- | --- | --- |
| `intel.enabled` | `false` | Enable the feed lookup |
| `intel.feed` | `threat-intel.txt` | Classpath or file path of the feed |
| `intel.defaultSeverity` | `HIGH` | Severity when a line omits one |

## NDR detectors

Four more detectors extend the existing `Detector` strategy, so they are identical in shape to the
original four and are still created by `DetectorFactory`. All five are off by default, so the
alert stream is unchanged until an operator asks for them. `createAll()` still returns the four
original detectors, and `createNdr()` returns the five network detection ones.

- `BeaconingDetector`: a source that talks to the same target on a steady rhythm. It learns the
  interval from consecutive events and accepts jitter inside a tolerance.
- `DataExfilDetector`: a source that sends more than `detection.exfil.maxBytes` to an address
  outside the internal prefixes inside one window.
- `LateralMovementDetector`: one source that reaches too many distinct hosts on management ports
  inside a window.
- `FloodDetector`: multiple sources that together send more than `detection.flood.maxConnections`
  connections to one destination inside a window.
- `ThreatIntelDetector`: the feed lookup above, expressed as a detector.

Every one of them keeps its per-source bookkeeping in a bounded map with a fixed cooldown, so a
long run cannot grow without limit.

| Key | Default | Meaning |
| --- | --- | --- |
| `detection.beaconing.enabled` | `false` | Enable beaconing detection |
| `detection.beaconing.minSamples` | `4` | Intervals needed before an alert |
| `detection.beaconing.jitterTolerance` | `0.25` | Allowed relative spread of the rhythm |
| `detection.beaconing.minIntervalSeconds` / `maxIntervalSeconds` | `5` / `900` | Accepted rhythm range |
| `detection.exfil.enabled` | `false` | Enable exfiltration detection |
| `detection.exfil.windowSeconds` / `maxBytes` | `300` / `5000000` | Window and byte ceiling per source |
| `detection.exfil.internalPrefixes` | `10.,192.168.,172.16. ...` | Addresses that do not count as outside |
| `detection.lateral.enabled` | `false` | Enable lateral movement detection |
| `detection.lateral.windowSeconds` / `maxHosts` | `120` / `4` | Window and distinct host ceiling |
| `detection.lateral.adminPorts` | `22,23,445,3389,5985` | Ports that count as management |
| `detection.flood.enabled` | `false` | Enable connection flood detection |
| `detection.flood.windowSeconds` / `maxConnections` | `60` / `100` | Window and connection ceiling per destination |
| `detection.flood.allowlist` | `` | Destinations exempt from flood counting |
| `detection.beaconing.maxTracked` / `cooldownSeconds` | `2000` / `300` | Bound and cooldown (exfil and lateral have the same pair) |

### Detector names and the type each reports

`AttackType` is a closed set of four values, and the dashboard, the filters and the reports all count
it. A detector therefore never invents a fifth value: its own name carries the precise meaning, and
the attack type names the bucket it is filed under. This is the mapping the pipeline uses.

| Detector name | Reports | Meaning | Wired in |
| --- | --- | --- | --- |
| `SignatureDetector` | `DOS_FLOOD`, `PORT_SCAN`, `DATA_TRANSFER` or `BRUTE_FORCE` | A payload keyword picks the bucket (`PORT_SCAN`, `DATA`, `LOGIN`), and a bad IP or port alone stays `DOS_FLOOD` | `createAll()` |
| `RateThresholdDetector` | `BRUTE_FORCE` | Events from one source above the rate ceiling in a window | `createAll()` |
| `PortScanDetector` | `PORT_SCAN` | Distinct ports and hosts reached by one source | `createAll()` |
| `AnomalyDetector` | `DATA_TRANSFER` | Byte volume far from the running mean | `createAll()` |
| `ThreatIntelDetector` | Follows the event | A feed hit: `LOGIN_ATTEMPT` files as `BRUTE_FORCE`, `DATA_TRANSFER` as `DATA_TRANSFER`, connections and requests as `PORT_SCAN` | `createNdr()` |
| `BeaconingDetector` | `PORT_SCAN` | Steady repeated contact between one source and one target | `createNdr()` |
| `DataExfilDetector` | `DATA_TRANSFER` | Outbound bytes to one address outside the internal prefixes | `createNdr()` |
| `LateralMovementDetector` | `PORT_SCAN` | One source reaching many hosts on management ports | `createNdr()` |
| `FloodDetector` | `DOS_FLOOD` | Connection flood to one destination from many sources | `createNdr()` |
| `MlFlowScorer` | `DATA_TRANSFER` | The nearest neighbour score for a finished flow | `IncidentResponseFacade` |
| `SiemCorrelator` | The newest contributing type | Cross detector signals and kill chains; a completed chain reuses the type of the alert that completed it | alert bus subscriber |

`DetectorFactory.create(name)` resolves a name by substring in that order, `createAll()` returns the
first four and `createNdr()` the next five, so the four value enum stays closed while the rule that
produced an alert is never ambiguous.

## Alert quality gate

`alerts.dedupe.enabled=true` inserts a seam between the detectors and the bus. `AlertGate` is one
method, `allow(Alert)`, and `AlertQualityGate` implements it with a per-key window and a severity
floor. The gate runs before the per-source cooldown is recorded, so a suppressed alert never
consumes the cooldown of the real one that follows. `GET /api/alert-quality` reports what it has
seen; a disabled gate reports zeros rather than pretending.

A repeat inside the window is not thrown away. `AlertGate.decide` answers with a `Decision` of
`DELIVERED`, `FOLDED` or `SUPPRESSED`, and a folded alert increments the `occurrences` counter of
the alert that fired first and moves its `lastSeen`. One fact is therefore one row that says "x23"
instead of twenty three rows that each say nothing. Folded alerts are re-emitted on the stream and
re-written to the store under the same id, so the feed replaces the row rather than appending a
second copy of it.

Order inside the gate: severity floor, then operator rules, then folding, then the storm cap. The
storm cap counts deliveries only and is measured over alert timestamps rather than the wall clock,
so a replay that runs at speed 0 meets the same limit as a live feed at real speed.

| Key | Default | Meaning |
| --- | --- | --- |
| `alerts.dedupe.enabled` | `true` | Fold repeats instead of publishing them |
| `alerts.dedupe.windowSeconds` | `60` | Window from the last sighting in which a repeat folds |
| `alerts.dedupe.maxKeys` | `5000` | Bounded key table |
| `alerts.minSeverity` | `LOW` | Severity floor |
| `alerts.maxPerMinute` | `600` | Delivery cap, `0` for no cap |
| `suppression.enabled` | `true` | Apply operator rules |
| `suppression.rules.file` | `config/suppression-rules.json` | Where the rules are kept |
| `suppression.maxRules` | `200` | Table size limit |

### Triage

`POST /api/alerts/{id}/status` moves one alert through an explicit transition table: `NEW` to
`ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED` or `FALSE_POSITIVE`, and any of those back to `NEW`.
A move outside the table answers 409 with the status the alert stayed at, which is a different
answer from 404, and every move is audited with the before and after state. The status lives on
the alert itself and in the `alerts` table, so it survives a restart.

A false positive answers with the rule it would take to silence that route, derived from the
alert's own detector, type, addresses and severity. It proposes; it does not silence. Creating the
rule is a separate `POST /api/suppression/rules` that is audited on its own, because "this alert
was wrong" and "stop showing me these" are two decisions.

### Suppression rules

`GET|POST /api/suppression/rules` and `DELETE /api/suppression/rules/{id}` manage a JSON file of
rules. A blank field is a wildcard and `maxSeverity` is a ceiling, so a rule written from a `LOW`
false positive cannot silence a `CRITICAL` on the same route. A rule that names nothing is refused
with 400 rather than quietly matching everything. The Admin page lists the table and can add or
remove rows; the Alerts page offers the proposed rule after a false positive.

## Flow anomaly model

The model is pure Java: k-means++ with a fixed seed, per-dimension standardisation, and a score
read off the distance distribution the model was trained on. The score of a flow is the share of
training flows that sit closer to their nearest centroid than it does, taken at the midpoint of the
ties, so 0.97 means "further out than 97% of what the model has seen" and nothing more. That is the
only claim an unlabelled feed can support. The first version divided the distance by the 95th
percentile instead, and on a real capture it saturated at 1.0 in six dimensions, which made every
evaluated flow look maximally anomalous; the rank keeps the same order without letting the ceiling
eat the signal. Six log-scaled features describe a flow.

Training runs on its own thread and never on the detection thread, and the status says `cold` while
there are too few samples, so a model with no opinion never reads as a clean bill of health.

An alerted pair is not evidence of normality. `ml.train.excludeAlerted=true` keeps the source and
destination of any alert out of the training buffer for `ml.train.exclusionSeconds`, so a model that
keeps learning during an attack is not taught that the attack is the baseline. `excluded` in the
status counts those flows; they are counted, not retained, and the buffer simply never sees them.

`GET /api/ml/status` reports the state, the sample count, the cluster count, the threshold, the
excluded count and the last training time. Alerts land in `DATA_TRANSFER` because the domain enum is
a closed set of four; the detector name `MlFlowScorer` and the description carry the precise meaning.

| Key | Default | Meaning |
| --- | --- | --- |
| `ml.enabled` | `false` | Score completed flows |
| `ml.k` | `4` | Clusters |
| `ml.minSamples` | `60` | Samples needed before the first model |
| `ml.retrainSeconds` | `300` | Background retrain interval |
| `ml.anomalyThreshold` | `0.9` | Score at which an alert is raised |
| `ml.maxTrainFlows` | `2000` | Bounded training buffer |
| `ml.seed` | `42` | k-means++ seed, for repeatable models |
| `ml.cooldownSeconds` / `ml.maxTrackedSources` | `300` / `2000` | Per-source suppression and bound |
| `ml.train.excludeAlerted` | `true` | Keep alerted pairs out of training |
| `ml.train.exclusionSeconds` | `300` | How long an alerted pair stays excluded |
| `ml.train.maxPairs` | `5000` | Bounded exclusion table |

### Evaluation against labels

An imported capture carries its ground truth. `ImportService` joins the label file only after a
flow has been replayed, so a label can never influence whether an alert fires, and it hands each
connection to the evaluation set with its label, whether a rule alerted for it, and the run it came
from. The same rows feed the model, taken from the exporter rather than from the flow recorder: the
recorder closes a flow on the next query and has no inbound byte counter, so a model trained on
that projection learns that every reply is empty and treats every real reply as an anomaly.

`POST /api/ml/evaluate` trains the model, scores every retained flow, and returns a confusion
matrix at the configured threshold with precision, recall, F1, false positive rate and accuracy, a
threshold sweep, one row per run, and the same numbers for the rule detectors alone over the same
flows. `GET /api/ml/evaluation` reports the set size, the class split and the run ids. Both are
admin only: an evaluation is a read, but a read that costs a training pass, and a viewer that can
start work can be used to start work.

A label listed in `ml.eval.benignLabels` is benign; every other label counts as an attack, so an
unknown label makes the evaluation pessimistic rather than flattering. A flow the label file does
not mention is counted as an attack too, which is why the sample label file covers every row.

| Key | Default | Meaning |
| --- | --- | --- |
| `ml.eval.sweepStart` / `sweepEnd` / `sweepStep` | `0.5` / `0.99` / `0.05` | Thresholds in the sweep |
| `ml.eval.maxRuns` | `5` | Recent runs kept for the per-run split |
| `ml.eval.maxSamplesPerRun` | `2000` | Bounded rows per run |
| `ml.eval.benignLabels` | `NORMAL,...` | Labels that count as benign |

On the bundled capture (1693 labelled flows, 409 attack, 1284 benign, 554 flows excluded from
training by the alert exclusion) the model scores F1 0.80 at the default threshold with 360 true
positives, 133 false positives and a false positive rate of 0.10, while the rules alone over the
same flows reach F1 0.03 with 8 true positives and 401 missed attacks. The rules are sharp about
the attack forms they were written for and blind to everything else; the model covers the volume on
similarity alone. Neither number is a claim that the model understands an attack.

### Limitations

The data is simulated. Every capture, label and attack behind those numbers comes from the exporter
in this repository, or from a capture an operator supplies together with its own label file. The
figures say how well the model separates that capture. They say nothing about a production sensor,
where benign traffic is not generated by the same code that generates the attacks, and where the
label file would have to be built from incident records rather than from a script.

The training set is also the scoring set: the same flows teach the clusters and are then scored, so
the model is measured on what it has already seen. A held-out split would report a lower F1, and a
future change should import twice, train on the first capture and evaluate on the second.

Excluding alerted pairs helps only while the rules are right. An attack that no rule notices is
learned as normal, and an alert on ordinary traffic hides that traffic from the model for the
exclusion window. The anomaly score is a similarity measure, not a verdict, which is why it ships
disabled and stays at `LOW` severity by default.

### Simulation noise

`sim.noise.enabled=true` bends the traffic the simulator produces without adding an attack type. On
the benign side, a share of flows become an unusual but legitimate spike to port 443, a failed retry,
or a service on a port the profile does not normally use, so a model that only knows one shape of
normal is tested rather than confirmed. On the attack side, a share of runs switch to a variant: a
scan offset well above the common ports, a brute force against RDP instead of SSH, or a flood
directed at 443 instead of 80. The variants keep the same `AttackType`, so the detector contract and
the enum stay unchanged, and the signature rules are supposed to miss them. Noise is off by
default, because a deterministic baseline is easier to explain than a realistic one.

| Key | Default | Meaning |
| --- | --- | --- |
| `sim.noise.enabled` | `false` | Turn the variants and benign noise on |
| `sim.noise.benignSpikeChance` / `benignSpikeBytes` | `0.03` / `2000000` | Legitimate backup spike |
| `sim.noise.retryChance` | `0.05` | Failed retry on ordinary traffic |
| `sim.noise.portSpreadChance` | `0.10` | Uncommon port on ordinary traffic |
| `sim.noise.attackVariantChance` | `0.25` | Share of attack runs that take a variant |
| `sim.noise.scanPortOffset` / `variantBrutePort` / `variantFloodPort` | `8000` / `3389` / `443` | Variant shapes |

## Correlation

`correlation.enabled=true` escalates a source that produces several distinct attack types inside
one window, once, instead of once per alert. The correlator subscribes to the same bus, ignores its
own alerts so it cannot feed itself, and keeps a bounded source table. `GET
/api/correlation/status` reports its rule and counters.

| Key | Default | Meaning |
| --- | --- | --- |
| `correlation.enabled` | `false` | Correlate cross-detector signals |
| `correlation.minSignals` | `2` | Distinct attack types that make a pattern |
| `correlation.windowSeconds` | `600` | Window the signals must fall inside |
| `correlation.cooldownSeconds` | `600` | One escalation per source per cooldown |
| `correlation.escalateSeverity` | `HIGH` | Severity of the distinct-type escalation |
| `correlation.maxSources` | `2000` | Bounded source table |
| `correlation.killChain.file` | `config/kill-chain.json` | Ordered stage rules; a missing file uses the built-in chain |

On top of that count, ordered kill chains are walked per source. A chain says a scan, then credential
guessing, then a transfer out is a campaign rather than three facts, and it lives in
`config/kill-chain.json` so a new pattern needs no rebuild. The stage index only moves forward and the
whole sequence has to fit inside the chain's window, measured from its first stage; a stage that
arrives out of order or too late does not match, so a source that guesses credentials and then scans
has not run that chain. A completed chain is published once as `Possible compromise: ...` at the
chain's own severity. With no file the built-in `recon-to-exfil` chain is used; a file that cannot be
read, names a stage outside the four attack types, or holds a chain with fewer than two stages is
reported through `chainProblem` and the built-in chain stays in force.

```json
{
  "chains": [
    {
      "id": "recon-to-exfil",
      "name": "Recon to exfiltration",
      "stages": ["PORT_SCAN", "BRUTE_FORCE", "DATA_TRANSFER"],
      "windowSeconds": 900,
      "severity": "CRITICAL",
      "note": "Scan, then credentials, then a transfer out"
    }
  ]
}
```

## Events, incidents and search

An event here is a detected alert: it is the fact the system records with a detector, a severity, a
route and a status, and it is what an incident timeline is built from. `GET /api/events` searches the
live ring plus the durable store, deduplicated by id and newest first, so history stays searchable
after the ring has moved on.

| Parameter | Meaning |
| --- | --- |
| `q` (or `text`) | Free text over the description, detector, route, type, severity and status |
| `severity` | `LOW`, `HIGH` or `CRITICAL` |
| `attackType` | One of the four attack types |
| `detector` | Substring of the detector name |
| `source`, `target` | Substring of the address |
| `simulated` | `true` for imported traffic, `false` for live |
| `from`, `to` | ISO instants |
| `limit`, `offset` | Page size and start, `limit` capped by `alerts.buffer.max` |

The answer is `{total, offset, limit, events}`. A malformed value answers 400 rather than an empty
list, because an empty result from a broken query reads as "nothing happened". `/api/alerts` accepts
the same filters and still answers a plain array, so existing callers are unchanged.

`GET /api/incidents/{id}` answers one incident with a derived timeline: each entry says whether it was
an `alert` or an `escalation`, and carries the time, severity, detector, attack type, route, alert id,
occurrence count and origin. The timeline is derived from the incident's own alerts rather than stored
in a second table that could drift. The Events page searches and tails, and the Incidents page shows
the timeline with a separate `Focus host` action.

## Containment

Containment records what an operator decided, for how long and why. One mode decides how far the
record goes: `off` records nothing, `ids` records actions but admits every event, and `ips` makes the
containment service the detection engine's admission predicate, so a contained source's events are
dropped before any detector sees them and the count is visible. When `containment.mode` is absent the
older `containment.enabled` and `containment.enforce` pair still decides the mode, so an existing
configuration keeps the behaviour it asked for. `containment.auto` may contain a source on its own
when an alert reaches the higher of `containment.autoSeverity` and `containment.minSeverity`, and every
automatic block also becomes a `MitigationTask` (`contain-<assetId>`), so it appears in the planner
next to the rest of the work.

Three safeguards stand between an order and a block. An address on `containment.allowlist` is never
contained, a burst above `containment.maxPerMinute` is refused, and a block whose removal would split
the topology is refused after re-planning the backbone without that host. Every refusal is counted
and reported. `POST /api/containment/mode` asks for the password again, because a mode change decides
whether the system drops traffic, and every mode change, block and release lands in the audit trail.
`GET /api/network` carries a `contained` array of `{ip, expiresAt, automatic}`, so the Hosts table,
the host panel and the map mark a contained address without a second request.

| Key | Default | Meaning |
| --- | --- | --- |
| `containment.mode` | `off` | `off`, `ids` or `ips` |
| `containment.auto` | `false` | Contain on a severe alert without an operator |
| `containment.autoMinutes` | `30` | Duration of an automatic block |
| `containment.autoSeverity` | `CRITICAL` | Severity that triggers the automatic block |
| `containment.minSeverity` | `LOW` | Lowest severity an automatic block may react to |
| `containment.maxDurationMinutes` | `1440` | Longest accepted block |
| `containment.maxBlocked` | `500` | Bounded block table |
| `containment.allowlist` | empty | Exact addresses, or prefixes ending in a star, that are never blocked |
| `containment.maxPerMinute` | `12` | Refuse more than this many blocks per minute; `0` disables |
| `containment.partitionCheck` | `true` | Refuse a block that would split the topology |

## Notifications

`notifications.enabled=true` keeps a bounded outbox of alerts at or above
`notifications.minSeverity` and fans them out to three channels: a console line in the event log,
an SMTP relay, and a webhook. Each channel has its own counters, and every attempt lands in a
short delivery history so "the webhook is down" can be checked against attempts rather than
guessed from silence. Escalations raised by the correlator are delivered through the same path
and marked in the outbox.

The webhook is the only channel that leaves the machine, so it carries the guards. A URL must be
`https` unless it names loopback and `notifications.allowInsecure=true`; it is resolved and
refused if it points at a private, loopback, link-local, multicast or unique-local address;
redirects are never followed. Delivery retries with exponential backoff, a circuit breaker opens
after repeated failures and closes after its cooldown, an hourly cap and a per-source cooldown keep
a storm from becoming a mail bomb, and the body is redacted and truncated before it is sent. The
webhook secret (`NTD_WEBHOOK_SECRET`) and the relay credentials (`NTD_SMTP_USER`,
`NTD_SMTP_PASSWORD`) are read from the environment and are never taken from configuration.

`GET /api/notifications` returns the outbox, the channel health, the effective limits and the
recent delivery history. `POST /api/notifications/test` (Admin) sends one probe through every
configured channel and reports each outcome; `POST /api/notifications/control` (Admin, password
re-entry) turns delivery on or off without changing the configured channels. Both are audited.

| Key | Default | Meaning |
| --- | --- | --- |
| `notifications.enabled` | `false` | Collect and deliver notifications |
| `notifications.minSeverity` | `HIGH` | Severity floor |
| `notifications.maxOutbox` | `200` | Bounded outbox |
| `notifications.console` | `true` | Write a delivered line to the event log |
| `notifications.webhook.url` | empty | Where to post; empty keeps it local |
| `notifications.allowInsecure` | `false` | Permit plain http to a loopback receiver only |
| `notifications.maxInFlight` / `webhook.timeoutMillis` | `8` / `2000` | Pool size and per-call timeout |
| `notifications.retries` / `backoffMillis` | `2` / `500` | Attempts after the first, and the base delay that doubles |
| `notifications.breakerThreshold` / `breakerCooldownSeconds` | `5` / `60` | Failures that open the circuit, and how long it stays open |
| `notifications.maxPerHour` / `cooldownSeconds` | `120` / `30` | Hourly cap and per-source-per-type cooldown; `0` disables |
| `notifications.maxBodyBytes` / `historyMax` / `redact` | `8192` / `200` / `true` | Payload cap, attempt history size, credential redaction |
| `notifications.email.enabled` | `false` | Use the SMTP channel |
| `notifications.email.host` / `port` / `from` / `to` | empty / `587` / `ntd@localhost` / empty | Relay and envelope; `to` accepts a comma separated list |
| `notifications.email.tls` / `timeoutMillis` | `true` / `5000` | STARTTLS requirement and socket timeout |

## Compliance and evidence

The compliance summary is one read that reports the state of every owning component: the store,
the audit trail, the outbox, containment, the evidence directory, the retention cutoff and a
control mapping. It is Admin only, because it describes the deployment rather than the network.

### Record exports

`GET /api/export/{kind}?format=csv|json` renders `alerts`, `events`, `incidents` or `flows`; CSV is
the default and an unknown kind or format answers 400. A cell is quoted when it holds a comma, a
quote or a line break, and a cell that starts with `=`, `+`, `-`, `@` or a control character is
prefixed with an apostrophe, so a value captured from traffic cannot run as a spreadsheet formula
when the file is opened. A JSON response is an envelope of `kind`, `generatedAt`, `count`,
`columns` and `rows`. Every response carries `X-Content-SHA256`, the digest of its own body, and a
`Content-Disposition` filename; a downloaded file can therefore be checked against what the server
reported. Rows are capped by `export.maxRows` and every export is audited as `export.<kind>`.

`GET /api/incidents/{id}/bundle` returns the incident detail the page shows plus a `manifest` with
the kind, a format version, the creation time, a record count and the SHA-256 of the detail. The
same digest is in the `X-Manifest-SHA256` header, and re-serialising the detail reproduces it, so a
receiver can verify a bundle without trusting the process that wrote it.

### Control mapping

The summary carries seven indicative ISO/IEC 27001:2022 Annex A controls: A.8.15 logging, A.8.16
monitoring, A.5.25 assessment, A.8.6 capacity, A.8.10 information deletion, A.8.11 data masking and
A.8.9 configuration management. Each row reports a status of PASS, PARTIAL or FAIL with the evidence
behind it and an `indicative` flag, and the response repeats a note that this is a mapping of what
the system can demonstrate, not a certification.

### Retention

Retention is expressed in minutes and is editable at runtime: an Admin session may
`POST /api/retention {"minutes": 60, "password": "<re-enter>", "sweepNow": true}`. The value is
validated between 5 minutes and one year, the change is audited with the previous value, and
`sweepNow` applies it immediately and reports how many rows were removed across every table,
including the model table. The default is `persistence.retentionMinutes`, and with the store off the
call still validates and answers `storeEnabled: false` rather than pretending to have swept.

### Forensics bundle

`POST /api/forensics/export` writes an evidence bundle: the flows and alerts of the moment, a
manifest file with the SHA-256 digest of each record, and a summary. The directory is
`forensics.dir`, each export is a timestamped folder, and the record counts are capped by
`forensics.maxFlows` and `forensics.maxAlerts` with an explicit truncated flag rather than a
silent cut. Every export is written to the audit trail. `forensics.enabled` is off by default and
the endpoint answers 409 while it is.

| Key | Default | Meaning |
| --- | --- | --- |
| `forensics.enabled` | `false` | Allow evidence export |
| `forensics.dir` | `evidence` | Root directory for bundles |
| `forensics.maxFlows` / `maxAlerts` | `5000` / `5000` | Per-export record caps |
| `export.maxRows` | `5000` | Rows returned by one table export |

## Benchmarks

`--benchmark [events]` measures the operations that run on every event and prints one row per
benchmark: event ingest, the four signature detectors, the NDR detectors, feature extraction, the
quality gate and k-means training. The scale defaults to 10000 events and is clamped to at least 200
so the numbers mean something. Each row runs a warm-up pass that is thrown away, then five timed
rounds, and reports the mean with p50, p95, p99 and max next to the operation and round counts, so
two runs can be compared and a reader can see what was measured. A zero-operation row reports zero
instead of dividing by zero.

`--soak [seconds]` runs the real engine under sustained load at `bench.soak.eventsPerSecond`
(2000 by default) and reports events offered, processed, dropped, alerts detected and delivered, rows
written, queue depth, throughput, heap, and two latency distributions: end to end from the queue, and
the time inside detection alone. Giving both switches runs the table first and the soak afterwards.

`GET /api/metrics` exposes the same counters from a running server: processed, dropped and queued
events, alerts detected and delivered, stream clients and frames, flows, store rows and queued rows,
model and replay state, heap and thread count. It needs a session, because the counters describe the
host, and the Admin page shows them in its operations panel.

`docs/benchmarks.md` records the machine, the commands, the measured tables, and the three hot-path
defects the measurements exposed: a fold-map scan on every delivered alert, a full active-flow scan on
every eviction, and a file write per alert on the detection thread.

## Guided tour

Start the server and open the portal:

```
java -jar target/threat-detection-1.0-SNAPSHOT.jar --web --port 8080
```

1. Sign in as admin.
2. Overview: start the simulation, then switch auto mode on, and watch the map, the alert feed and
   the counters. Starting the simulation alone fills the queue; auto mode is what produces traffic.
3. Attack lab: run a port scan, then the multi-stage preset, and watch the kill chain complete on the
   Incidents page.
4. Flows: the Live switch shows what the recorder is aggregating, and Stored shows the same rows read
   back from the durable store.
5. Admin: the operations panel reads back the model, correlation, containment, notifications,
   compliance and audit state. Metrics on the same page are the counters `GET /api/metrics` returns.
6. Offline: `--import-zeek` the sample capture, then read it back from the Flows page.

## Limitations

What this is not, stated plainly so the numbers are read correctly.

- **The data is simulated.** Every attack, capture and label comes from the exporter in this
  repository, or from a capture an operator supplies with its own label file. Detection quality on a
  live sensor would depend on traffic this code has never seen.
- **ML figures are in-sample.** The evaluation scores the same flows the model was trained on, so
  the reported F1 is an upper bound rather than a held-out estimate. All figures in the README and
  in the Admin evaluation panel come from simulated data or the one bundled capture; none carry
  over to a production sensor.
- **It is one process.** The store is a single SQLite file with one writer, the detector list is
  fixed at startup, and nothing is replicated. A deployment would put this behind a collector and
  give the store its own server.
- **The topology is the sample graph.** Eighteen assets and twenty one links, loaded at startup. The
  partition safeguard, the planner and the containment checks are all honest about that graph, but
  they have not been exercised against a discovered or edited one.
- **The detectors are heuristics.** Each rule is tuned for the shapes the simulator produces, which
  is exactly the shape a real sensor would not have. The behavioural detectors ship disabled for
  that reason.
- **The model has its own limits**, listed under the flow anomaly model above: the training set is
  the scoring set, and exclusion only helps while the rules are right.
- **TLS is the proxy's job.** The server speaks plain HTTP and leaves HSTS to whatever terminates
  TLS in front of it, which is what `docker-compose.yml` does with Caddy. Docker, TLS termination
  and long soak runs have not been exercised as part of this build.
- **Accounts live in one properties file.** There is no directory service, no per tenant isolation
  and no self service password reset; the three accounts and their roles are the whole model.
- **The dashboard is a demonstration surface.** It renders what the API returns and keeps no
  history of its own, so what a page shows is what the server still holds.

## Security notes

`docs/security.md` is the reference: deployment modes, accounts and roles, password policy, re-authentication, throttling, headers, audit rules, container hardening and the dependency review.

The short version. `src/main/resources/config.properties` holds the account table, the detector thresholds and the simulation ranges. Passwords are PBKDF2WithHmacSHA256 hashes (`pbkdf2$iterations$salt$hash`); the demo seed uses one password per username so the walkthrough stays simple. In production mode the server refuses to start unless every account has a real credential, given either through `NTD_ADMIN_PASSWORD` and friends or as a replacement hash. Plaintext credentials are checked against `auth.password.minLength` (12, floor of 8) and `auth.password.requireClasses`.

Mutating API calls must echo the `csrf` cookie in an `X-CSRF-Token` header. The web client does this on login and on the first `GET /api/state`. Failed logins are counted per account and per address; five failures within five minutes answer `429` with a `Retry-After` header and never say whether the account exists.

Containment mode, notification control and retention ask for the password again (`auth.reauth.enabled`), throttle repeated failures, and audit both outcomes. The login session is rotated on success, which defeats session fixation, and the `csrf` token is replaced with it. The session cookie is `HttpOnly` and `SameSite=Lax`; `auth.session.secureCookie=true` adds `Secure` for a TLS deployment, and `auth.session.absoluteTimeoutSeconds` ends a session that has been kept warm past its hard lifetime.

Every response carries CSP, `nosniff`, `X-Frame-Options: DENY`, a referrer policy, `Permissions-Policy` and the cross-origin isolation headers. `auth.hsts.enabled=true` adds HSTS, which is only correct behind TLS. Bodies above `http.maxBodyBytes` answer `413` before a handler sees them, a mismatched `Origin` answers `403`, and an unexpected exception answers `500` with `{"error":"internal server error"}` while the stack trace goes to the log. `GET /healthz` is unauthenticated and returns only liveness.

## Audit trail

Every security relevant action is recorded in a bounded ring with the actor, the action, the target, the outcome and a detail line: sign in, sign out, every refused call, containment orders and releases, evidence exports and configuration reads. `GET /api/audit` is Admin only and reports the newest entries, the current capacity and the denied and failed counts. A refusal is counted as it happens, so a viewer hammering an Admin endpoint leaves a trail instead of an empty page.

| Key | Default | Meaning |
| --- | --- | --- |
| `audit.enabled` | `true` | Record the trail |
| `audit.maxRecords` | `2000` | Bounded ring size |
| `audit.api.max` | `200` | Entries one response may return |
| `auth.session.rotateOnLogin` | `true` | Issue a new session id on sign in |
| `auth.session.absoluteTimeoutSeconds` | `43200` | Hard session lifetime from sign in, `0` disables |

With `persistence.enabled=true` every entry is written through to the `audit_entries` table as an insert and restored on startup, so the trail survives a restart. The retention sweep is the only statement that removes a row, and it records `retention.update` before it runs.

## Docker

```
docker build -t threat-detection .
docker run --rm -p 8080:8080 -e PORT=8080 threat-detection
```

The image runs `Main --web` and uses `PORT` when it is set, otherwise 8080. The runtime stage runs as the unprivileged user `ntd` (uid 10001), keeps its store in `/app/data` and its evidence bundles in `/app/evidence`, and declares a `HEALTHCHECK` against `/healthz`.

`docker-compose.yml` adds a Caddy proxy that terminates TLS on port 8443 using `deploy/Caddyfile`, so `https://localhost:8443` works after the compose stack is healthy:

```
docker compose up --build
```

It starts in demo mode. The file contains the commented production block: enable persistence, set `app.demoMode=false` through `JAVA_TOOL_OPTIONS`, and supply the three passwords from a `.env` file. HSTS is set at the proxy and left off in the app, because the app only sees plain HTTP on the compose network.
