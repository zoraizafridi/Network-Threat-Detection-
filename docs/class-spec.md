PROJECT CONTEXT
Course CT-263 Object-Oriented Analysis and Design (CCA live demo + CCP report).
System: "Network Threat Detection and Cyber Security Monitoring System".
Java 17 backend with a React web front end. No Swing. Simulated network, rule-based detection plus an
optional unsupervised model, alerts, risk scores, response planner (Kruskal backbone + DP task
assignment), incident report, durable store.
Same codebase as a DAA project; the OOAD report centres on UML + patterns + demo.
Brief rule: report diagrams must match the lab demo exactly.
Report must contain the 8 UML diagrams (use case, activity, class, object, component,
sequence, communication, deployment).
Tool: Modelio 5.4. The class model has 141 elements across 23 packages after the move from Swing to web,
the monitoring phases, benchmarks, NDR behavioural detectors and flood detection. Nested records are
listed with their owner and not counted.

STATUS
Done: backend (domain, simulation, detection, service, response, util, flows, persistence, security,
zeek, intel, ml, correlation, containment, notify, forensics, compliance, bench, export, imports, web)
with tests, DAA planners, class, component, use case and activity diagrams drawn, and the run measured
by benchmarks.md.
To do: the object, sequence, communication and deployment diagrams from a real run, then the reports.

RULES AND DECISIONS
- Packages: 23 packages (pk.ooad.ntd, domain, simulation, detection, service, response, util, web, flows,
  persistence, security, zeek, intel, ml, correlation, containment, notify, forensics, compliance, bench,
  export, imports). No Swing or AWT.
- Dependency rule:
  - domain imports nothing from other project packages.
  - simulation and detection depend only on domain and util.
  - response depends only on domain.
  - service depends on domain, detection, simulation, response, util.
  - web depends only on service (IncidentResponseFacade), domain (read only), detection.AlertListener
    and detection.AlertGate. It reads the newer services through facade getters and never constructs
    them, so the wiring stays in one place.
  - The entry class Main may depend on any package and passes port and seed to web.
  - bench is a driver like Main: it may reach any package, it owns no state, and nothing in the model
    depends on it. Every other package depends on it in no direction.
- Show a relationship as an arrow OR an attribute, never both.
- Omit getters/setters except where listed. Mark abstract classes and static members.
- NetworkEvent is immutable with NO "malicious" field (detectors never see ground truth).
- Patterns, only these 5: Strategy (Detector + 9 subclasses), Observer (AlertBus/AlertListener/AlertUpdateListener),
  Factory (AssetFactory, AlertFactory, DetectorFactory), Singleton (ConfigManager, EventLog),
  Facade (IncidentResponseFacade).
- Threading: simulator thread -> BlockingQueue -> detection thread -> AlertBus -> StreamBroadcaster
  -> SSE to browsers. Web handlers call the facade under one lock.
- 9 detectors. CreateAll() builds SignatureDetector (bad IP/port/payload), RateThresholdDetector
  (failed logins in a window), PortScanDetector (distinct ports/hosts in a window) and AnomalyDetector
  (Welford running mean/stddev per host, z-score > 3, warm-up, allowlist, no baseline update on flagged values).
  CreateNdr() builds BeaconingDetector (interval regularity per source, destination and port),
  DataExfilDetector (cumulative bytes towards an external prefix), LateralMovementDetector (distinct
  admin hosts per source), ThreatIntelDetector (indicator match) and FloodDetector (connection volume
  towards one destination in a window).
- Alert cooldown/de-duplication in DetectionEngine. All thresholds come from ConfigManager.
- The web package and the client contain no detection, risk, Kruskal or DP logic.
- The newer capabilities are seams, not rewrites: AlertGate is one method, the admission predicate is
  one Predicate, the quality gate is a decorator of the alert path, and the five NDR detectors extend
  the existing Detector strategy. No pattern was added; the five above still cover the whole model.
- Every later feature is off by default in config.properties except flow recording, the audit trail
  and the Zeek importer, so with the shipped configuration behavior matches the phase 0 baseline.

ENUMS
AssetType: SERVER, WORKSTATION, ROUTER, IOT_DEVICE
AssetStatus: NORMAL, SUSPICIOUS, COMPROMISED
LinkStatus: NORMAL, COMPROMISED
Severity: LOW, HIGH, CRITICAL
AttackType: PORT_SCAN, BRUTE_FORCE, DOS_FLOOD, DATA_TRANSFER
EventType: CONNECT, LOGIN_ATTEMPT, REQUEST, DATA_TRANSFER
IncidentStatus: OPEN, MITIGATED, CLOSED   (package domain)
AlertStatus: NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE   (package domain)
LogLevel: INFO, WARN, ERROR               (package util)

PACKAGE pk.ooad.ntd (1)
Main: +{static}main(args:String[]):void +{static}replayZeek(file:String,labels:String,speed:int,config:String):void

PACKAGE domain (33 elements incl. 8 enums)
NetworkAsset {abstract}: -id:String -name:String -ip:String -type:AssetType -criticality:int
  -riskScore:double -status:AssetStatus | +addRisk(delta:double):void +setStatus(s:AssetStatus):void
  +resetRisk():void +{abstract}getDefaultRiskWeight():double +{abstract}getTypicalPorts():List<Integer>
Server: -services:List<String> | +getDefaultRiskWeight() +getTypicalPorts()
Workstation: -owner:String | same two ops
Router: -interfaceCount:int | same two ops
IoTDevice: -firmwareVersion:String -defaultCredentials:boolean | same two ops
AssetFactory <<Factory>>: +create(type:AssetType,id:String,name:String,ip:String,criticality:int):NetworkAsset
Link: -id:String -baseCost:double -bandwidth:double -status:LinkStatus |
  +getOtherEnd(a:NetworkAsset):NetworkAsset +connects(a:NetworkAsset):boolean +markCompromised():void +reset():void
  (endpoints come from the association Link -> NetworkAsset [2], not attributes)
Network: (assets/links come from compositions) | +addAsset +removeAsset(id) +addLink +getAsset(id)
  +findByIp(ip) +getNeighbours(a):List<NetworkAsset> +getLinksOf(a):List<Link>
  +getCompromisedLinks():List<Link> +isConnected():boolean +resetAll():void
TopologyLoader: +{static}loadSample():Network +{static}loadFromFile(path:String):Network
NetworkEvent <<record>>: id:long timestamp:Instant sourceIp:String destIp:String port:int
  bytes:long type:EventType success:boolean payload:String simulated:boolean
Alert {abstract}: -id:String -timestamp:Instant -severity:Severity -attackType:AttackType
  -sourceIp:String -targetIp:String -detectorName:String -description:String -occurrences:AtomicInteger
  -firstSeen:Instant -lastSeen:Instant -status:AlertStatus -simulated:boolean |
  +{abstract}getRiskIncrement():double +fold(now:Instant):void +moveTo(next:AlertStatus):void
LowAlert, HighAlert, CriticalAlert: +getRiskIncrement():double
AlertFactory <<Factory>>: +create(sev:Severity,type:AttackType,src:String,dst:String,detector:String,desc:String,time:Instant):Alert
User {abstract}: -username:String -passwordHash:String | +checkPassword(raw:String):boolean
  +{abstract}canLaunchAttack() +{abstract}canRunPlanner() +{abstract}canConfigure() +{abstract}canManageUsers():boolean
Admin (all true), SecurityAnalyst (launch/plan/export true; configure/manage false), Viewer (all false)
AnalystTeam: -id:String -name:String -skills:Set<String> -capacity:int -available:boolean | +canHandle(t:MitigationTask):boolean
MitigationTask: -id:String -target:NetworkAsset -value:int -cost:int -requiredSkill:String -daysUnpatched:int
  (value is the base value; the facade computes the final decayed value once, before the DP,
   as value * (1 + decay.rate * daysUnpatched))
AuthenticationException (extends Exception)
BackboneResult: -chosenLinks:List<Link> -totalWeight:double -connected:boolean -unreachable:List<NetworkAsset>
AssignmentResult: -assignments:Map<AnalystTeam,List<MitigationTask>> -totalValue:int -excluded:List<MitigationTask> -stateCount:long
ResponsePlan: has composition to BackboneResult (backbone) and AssignmentResult (assignment)

PACKAGE simulation (10)
TrafficSimulator: -clock:Clock -random:Random -queue:BlockingQueue<NetworkEvent> -running:AtomicBoolean
  -autoMode:boolean -noise:SimulationNoise | +start() +stop() +reset() +setAutoMode(on:boolean)
  +injectAttack(type:AttackType,srcIp:String,dstIp:String):void +generateNormalEvent():NetworkEvent
  +getEventQueue():BlockingQueue<NetworkEvent>
HostProfile: -meanBytes:double -stdBytes:double -commonPorts:List<Integer> -eventsPerSecond:double
AttackGenerator {abstract}: +{abstract}generate(src:String,dst:String,now:Instant,rnd:Random):List<NetworkEvent>
PortScanGenerator, BruteForceGenerator, DosFloodGenerator, DataTransferGenerator: same generate()
AttackRecord (tests only): -type:AttackType -source:String -target:String -startTime:Instant
ScenarioService: -facade:IncidentResponseFacade | +run(name:String):Preset
  Preset <<record, nested>>: id:String name:String description:String attackType:AttackType
SimulationNoise: -enabled:boolean -benignSpikeChance:double -benignSpikeBytes:long -retryChance:double
  -portSpreadChance:double -attackVariantChance:double -scanPortOffset:int -variantBrutePort:int -variantFloodPort:int

PACKAGE detection (20)
AlertListener <<interface, Observer>>: +onAlert(a:Alert):void
AlertUpdateListener <<interface, Observer>>: +onAlertUpdated(a:Alert):void
AlertBus <<Observer>>: +subscribe(l) +unsubscribe(l) +publish(a:Alert) +publishUpdate(a:Alert)
Detector {abstract} <<Strategy>>: #name:String | +{abstract}analyze(e:NetworkEvent):Optional<Alert> +getName():String +reset():void
SignatureDetector: -badIps:Set<String> -badPorts:Set<Integer> -payloadPatterns:List<Pattern>
RateThresholdDetector: -windowSeconds:int -maxFailures:int -failuresBySource:Map<String,Deque<Instant>> | -prune(q,now)
PortScanDetector: -windowSeconds:int -maxDistinctPorts:int -maxDistinctHosts:int -touches:Map<String,Deque<Touch>>
AnomalyDetector: -zThreshold:double -warmupCount:int -allowlist:List<String> (stats via composition to RunningStats)
RunningStats: -count:long -mean:double -m2:double | +update(x:double) +getStdDev():double +zScore(x:double):double
DetectorFactory <<Factory>>: +create(name:String):Detector +createAll():List<Detector> +createNdr():List<Detector>
DetectionEngine: -queue:BlockingQueue<NetworkEvent> -worker:Thread -running:AtomicBoolean -cooldownSeconds:int
  -lastAlertAt:Map<String,Instant> -eventObservers:List<Consumer<NetworkEvent>> -alertGate:AlertGate
  -admission:Predicate<NetworkEvent> -droppedEvents:AtomicLong |
  +start() +stop() +addDetector(d) +reset() +addEventObserver(o) +setAlertGate(g) +setAdmission(p)
  +getDroppedEvents():long +processNow(e:NetworkEvent):void -process(e:NetworkEvent) -notifyObservers(e)
AlertGate <<interface>>: +allow(a:Alert):boolean +decide(a:Alert):Decision
  Decision <<enum, nested>>: DELIVERED, FOLDED, SUPPRESSED
AlertQualityGate (implements AlertGate): -dedupeEnabled:boolean -windowSeconds:int
  -minimumSeverity:Severity -maxKeys:int -stormLimit:int -suppression:SuppressionRules
  -delivered:Map<String,Alert> | +allow(a) +decide(a):Decision +stats():Stats +reset()
  Stats <<record, nested>>: raw delivered folded suppressed stormSuppressed ratio
AlertRegistry (implements AlertUpdateListener): -alerts:Map<String,Alert> | +register(a:Alert):void +get(id:String):Alert
BeaconingDetector (extends Detector): -minSamples:int -jitterTolerance:double -minIntervalMillis:long
  -maxIntervalMillis:long -maxTracked:int -cooldownMillis:long -allowlist:List<String> -series:Map<String,Series>
DataExfilDetector (extends Detector): -windowMillis:long -maxBytes:long -maxTracked:int
  -cooldownMillis:long -allowlist:List<String> -internalPrefixes:List<String> -windows:Map<String,Window>
LateralMovementDetector (extends Detector): -windowMillis:long -maxHosts:int -maxTracked:int
  -cooldownMillis:long -adminPorts:Set<Integer> -sources:Map<String,Source>
ThreatIntelDetector (extends Detector): -intel:ThreatIntel -enabled:boolean | +attackTypeFor(t:EventType):AttackType
FloodDetector (extends Detector): -enabled:boolean -windowMillis:long -maxConnections:int
  -maxTracked:int -cooldownMillis:long -allowlist:List<String> -windows:Map<String,Window>
SuppressionRules: -rules:List<Rule> -file:Path | +shouldSuppress(a:Alert):boolean +addRule(r:Rule):void +removeRule(id:String):boolean
  Rule <<record, nested>>: id detector attackType sourceIp targetIp maxSeverity note createdBy createdAt

PACKAGE service (9)
IncidentResponseFacade <<Facade>>: +login(u:String,p:String):User +start() +stop() +reset() +setAutoMode(on:boolean)
  +isRunning():boolean +isAutoMode():boolean +launchAttack(type:AttackType,src:String,dst:String)
  +runResponse():ResponsePlan +generateReport():String +exportReport(path:String) +addAlertListener(l:AlertListener)
  +getNetwork():Network +getIncidents():List<Incident> +getFlowRecorder():FlowRecorder
  +getMlFlowScorer():MlFlowScorer +getPersistenceService():PersistenceService +getAuditLog():AuditLog
  +getAlertQualityGate():AlertQualityGate +getSiemCorrelator():SiemCorrelator +getContainmentService():ContainmentService
  +getNotificationService():NotificationService +getEvidenceExporter():EvidenceExporter
  +getComplianceService():ComplianceService +getIntelService():IntelService +getScenarioService():ScenarioService
  +getImportService():ImportService +getExportService():ExportService +restore():void +shutdown():void
RiskScorer (implements AlertListener): -cap:double -compromiseThreshold:double -decayPerTick:double |
  +onAlert(a) +decay() +reset() -markAdjacentLinks(asset:NetworkAsset)
IncidentManager (implements AlertListener): -incidents:Map<String,Incident> -windowSeconds:int |
  +onAlert(a) +getOpenIncidents():List<Incident> +getAllIncidents():List<Incident> +reset()
Incident: -id:String -sourceIp:String -alerts:List<Alert> -status:IncidentStatus -openedAt:Instant |
  +addAlert(a) +setStatus(s)
AuthService: -users:Map<String,User> -policy:SecurityPolicy | +authenticate(u:String,p:String):User
  +reauthenticate(u:String,p:String):boolean
SOC: -engine:DetectionEngine -teams:List<AnalystTeam> -capacity:int | +getEngine():DetectionEngine +getTeams():List<AnalystTeam>
ReportGenerator: +generate(net:Network,incidents:List<Incident>,plan:ResponsePlan):String
AlertLogger (implements AlertListener): +onAlert(a:Alert):void
IntelService: -intel:ThreatIntel -detector:ThreatIntelDetector | +reload(raw:String):ThreatIntel +status():Status

PACKAGE response (3)
BackbonePlanner: +computeBackbone(net:Network):BackboneResult   (Kruskal algorithm on Link baseCost)
AssignmentPlanner: +assign(tasks:List<MitigationTask>,teams:List<AnalystTeam>):AssignmentResult   (DP 0-1 knapsack)
UnionFind: -parent:int[] -rank:int[] | +find(i:int):int +union(i:int,j:int):boolean

PACKAGE flows (3)
FlowRecord <<record>>: id:String srcIp:String dstIp:String srcPort:int dstPort:int protocol:String
  bytesOut:long bytesIn:long packets:long startTime:Instant endTime:Instant flags:List<String>
  label:String simulated:boolean ended:boolean | +durationMs():long
FlowQuery <<record>>: srcIp:String dstIp:String port:Integer from:Instant to:Instant limit:int
  includeActive:boolean | +{static}all(limit:int):FlowQuery -matches(f:FlowRecord):boolean
FlowRecorder (implements Consumer<NetworkEvent>): -enabled:boolean -idleTimeoutMillis -maxRecords
  -maxActiveFlows -retentionMillis -udpPorts:Set<Integer> -labelRules:List<LabelRule>
  -active:Map<String,Mutable> -closed:Deque<FlowRecord> -sequence:long -watermark:Instant |
  +accept(e:NetworkEvent):void +query(q:FlowQuery):List<FlowRecord> +reset():void +isEnabled():boolean
  -close(key:String):void -expireIdle():void -purgeExpired():void

PACKAGE persistence (25)
RecordStore <<interface>>: +close():void
AlertRepository <<interface>>: +insertBatch(l):void +recent(limit):List<AlertRecord> +deleteBefore(cutoff):int +count():int
FlowRepository <<interface>>: +insertBatch(l):void +recent(limit):List<FlowRecord> +deleteBefore(cutoff):int +count():int
InMemoryRecordStore (implements RecordStore): +close():void
InMemoryAlertRepository (implements AlertRepository): +insertBatch(l) +recent(limit) +deleteBefore(cutoff) +count()
InMemoryFlowRepository (implements FlowRepository): +insertBatch(l) +recent(limit) +deleteBefore(cutoff) +count()
SqliteAlertRepository (implements AlertRepository): -table:SqliteTable<AlertRecord> | +insertBatch +recent +deleteBefore +count
SqliteFlowRepository (implements FlowRepository): -table:SqliteTable<FlowRecord> | +insertBatch +recent +deleteBefore +count
SqliteTable<T>: -database:Database -spec:TableSpec<T> | +insertBatch(l) +recent(limit) +deleteBefore(cutoff) +count()
Database: -writer:Connection -reader:Connection -file:Path | +writer() +reader() +file() +close()
  (SQLite WAL mode, PRAGMA user_version schema migration)
Stores: +{static}memory():RecordStore +{static}sqlite(file:Path):RecordStore
TableSpec<T>: -name:String -ddl:String -columns:List<String>
TableSpecs: ALERT, FLOW, INCIDENT, CONTAINMENT, AUDIT, NOTIFICATION, MANIFEST, MODEL
WriteBehindQueue<T>: -name:String -capacity:int -batchSize:int -pending:Deque<T> | +offer(item):boolean +flush(ms):boolean +close()
PersistenceService (implements AlertListener, AutoCloseable): -settings:PersistenceSettings -database:Database
  -flows:FlowRepository -alerts:AlertRepository -flowQueue -alertQueue -sweeper:ScheduledExecutorService |
  +recordFlow(r) +onAlert(a) +storedFlows(limit) +storedAlerts(limit) +status() +sweepNow():int +close()
PersistenceSettings <<record>>: enabled:boolean databasePath:Path queueCapacity:int batchSize:int
  flushIntervalMillis:long retentionMinutes:int sweepMinutes:int
PersistenceStatus <<record>>: enabled:boolean databasePath:String flowRows:int alertRows:int
  queuedRows:long droppedRows:long writtenRows:long lastFlushAt:String lastError:String
AlertRecord <<record>>: id:String timestamp:Instant severity:String attackType:String sourceIp:String
  targetIp:String detector:String description:String occurrences:int firstSeen:Instant lastSeen:Instant status:String simulated:boolean
AuditRecord <<record>>: sequence:long timestamp:Instant actor:String action:String target:String outcome:String detail:String
ContainmentRecord <<record>>: ip:String blockedAt:Instant expiresAt:Instant reason:String actor:String automatic:boolean
IncidentRecord <<record>>: id:String sourceIp:String status:String openedAt:Instant alertCount:int alertIds:String
ManifestRecord <<record>>: directory:String createdAt:Instant filesCount:int totalBytes:long manifestSha256:String actor:String
ModelSummaryRecord <<record>>: trainedAt:Instant samples:int clusters:int threshold:double anomalyCount:int excludedCount:int
NotificationRecord <<record>>: id:String timestamp:Instant channel:String destination:String status:String detail:String
PersistenceException (extends RuntimeException)

PACKAGE security (2)
AuditLog: -enabled:boolean -maxRecords:int -entries:Deque<AuditRecord> -sequence:long -denied:long -failed:long |
  +record(actor,action,target,outcome,detail) +recent(limit):List<AuditRecord> +size():int +reset()
  Outcome <<enum, nested>>: ALLOWED, DENIED, FAILED
SecurityPolicy: -demoMode:boolean -minLength:int -requireClasses:boolean |
  +isDemoMode():boolean +checkPassword(u:String,p:String):boolean +banner():String

PACKAGE zeek (2)
ZeekConnLogParser: -maxFlows:int | +parse(file:Path):ZeekImportResult +parse(content:String,source:String):ZeekImportResult
ZeekImportResult <<record>>: source:String linesRead:long flowsParsed:long skipped:long
  firstTimestamp:Instant lastTimestamp:Instant hosts:Set<String> problems:List<String> records:List<FlowRecord>

PACKAGE intel (3)
IndicatorType <<enum>>: IP, DOMAIN, SHA256
IntelEntry <<record>>: type:IndicatorType value:String label:String severity:Severity expiresAt:Instant source:String
ThreatIntel: -entries:List<IntelEntry> -skipped:long | +{static}fromConfig() +match(ip:String):Optional<IntelEntry>
  +matchDomain(d:String):Optional<IntelEntry> +matchHash(h:String):Optional<IntelEntry>

PACKAGE ml (6)
FlowFeatures <<record>>: values:double[] | SIZE:int = 6 | +value(i):double
FeatureVector: +{static}of(f:FlowRecord):FlowFeatures
KMeans: +{static}fit(points,k,maxIterations,seed):Result
  Result <<record, nested>>: centroids:double[][] assignments:int[] inertia:double iterations:int
AnomalyModel: -mean:double[] -deviation:double[] -centroids:double[][] -scale:double -samples:int |
  +{static}train(samples,k,maxIterations,seed):AnomalyModel +score(f):double +distance(f):double
MlFlowScorer (implements AlertListener, AutoCloseable): -alertBus:AlertBus -training:Deque<FlowFeatures> -model:AnomalyModel |
  +onFlow(f:FlowRecord) +train():boolean +score(f):double +status():Status +reset() +close()
  Status <<record, nested>>: state:String samples:int clusters:int threshold:double scored:long anomalies:long alerts:long excluded:long
EvaluationService: -runs:Map<String,List<Row>> | +record(runId,flow,label,alerted):void +evaluate(k,threshold):Report
  Report <<record, nested>>: chosen:Point best:Point sweep:List<Point> rules:Point runs:List<RunReport>

PACKAGE correlation (2)
KillChainRules: -chains:List<Chain> -file:Path | +chains():List<Chain>
  Chain <<record, nested>>: id:String name:String stages:List<AttackType> windowSeconds:int severity:Severity note:String
SiemCorrelator (implements AlertListener): -bus:AlertBus -enabled:boolean -minSignals:int -windowSeconds:int
  -cooldownSeconds:int -killChains:KillChainRules | +onAlert(a:Alert) +status():Status +reset()

PACKAGE containment (2)
ContainmentSafeguards: -allowlist:List<String> -maxPerMinute:int -partitionCheck:boolean |
  +check(ip:String,net:Network):Optional<String>
ContainmentService (implements AlertListener): -clock:Clock -enabled:boolean -auto:boolean -enforce:boolean
  -safeguards:ContainmentSafeguards -blocked:Map<String,ContainmentRecord> |
  +admit(e:NetworkEvent):boolean +contain(ip,minutes,reason,actor):ContainmentRecord +release(ip):boolean
  +isBlocked(ip):boolean +active():List<ContainmentRecord> +onAlert(a) +status():Status +reset()
  Mode <<enum, nested>>: OFF, IDS, IPS

PACKAGE notify (4)
Mailer <<interface>>: +send(to:String,subject:String,body:String):void
SmtpMailer (implements Mailer): -host:String -port:int -username:String -password:String -tls:boolean | +send(to,subject,body):void
WebhookGuard: -allowInsecure:boolean | +validate(url:String):URI
NotificationService (implements AlertListener): -enabled:boolean -mailer:Mailer -webhookUrl:String |
  +onAlert(a:Alert) +status():Status +sendTest(to:String):boolean +reset()

PACKAGE export (1)
ExportService: +exportAlerts(alerts,format):Table +exportEvents(events,format):Table
  +exportIncidents(incidents,format):Table +exportFlows(flows,format):Table
  Table <<record, nested>>: contentType:String body:byte[] filename:String sha256:String rowCount:int

PACKAGE imports (2)
ImportLabels: +{static}parse(content:String,source:String):Map<String,String>
ImportService: -facade:IncidentResponseFacade | +replay(logContent,logName,labelsContent,labelsName,speed):Report
  Report <<record, nested>>: flows:long events:long alerts:long detected:long folded:long labels:List<LabelStat>

PACKAGE forensics (1)
EvidenceExporter: -enabled:boolean -directory:Path -maxFlows:int -maxAlerts:int |
  +export(actor,flows,alerts,audit,incidents):Bundle +isEnabled():boolean +directory():Path
  Bundle <<record, nested>>: directory:String createdAt:String files:int bytes:long manifestSha256:String actor:String

PACKAGE compliance (1)
ComplianceService: -persistence:PersistenceService -audit:AuditLog -notifications:NotificationService
  -containment:ContainmentService -forensics:EvidenceExporter -config:ConfigManager |
  +summary():Summary +controls():List<ControlResult>
  Summary <<record, nested>>: storeEnabled:boolean databasePath:String storedFlows:int storedAlerts:int

PACKAGE bench (2)
Benchmarks: +{static}run(scale:int):List<Result> +{static}report(results):String
  Result <<record, nested>>: name:String operations:long rounds:int samples:long meanMicros:double
   p50Micros:double p95Micros:double p99Micros:double maxMicros:double operationsPerSecond:double
Soak: +{static}run(facade:IncidentResponseFacade,seconds:int):Report
  Report <<record, nested>>: targetRate:int offered:long processed:long dropped:long detected:long alerts:long

PACKAGE web (5)
WebServer: -app:Javalin -facade:IncidentResponseFacade -lock:ReentrantLock | +start(port:int):void +stop():void +port():int
ApiRoutes: -facade:IncidentResponseFacade -broadcaster:StreamBroadcaster -lock:ReentrantLock | +register(app:Javalin):void
LoginThrottle: -attempts:Map<String,Deque<Instant>> | +allow(key:String):boolean +retryAfterSeconds(key:String):long
StreamBroadcaster (implements AlertListener): -clients:Set<SseClient> -recent:Deque<Alert> | +onAlert(a:Alert):void
  +addClient(c):void +removeClient(c):void +getRecentAlerts(limit):List<Alert> +broadcastState():void
Dtos: nested records only (AssetDto, LinkDto, AlertDto, IncidentDto, FlowDto, PlanDto, StateDto), no behaviour

PACKAGE util (4)
ConfigManager <<Singleton>>: -{static}instance -props:Properties -ConfigManager() | +{static}getInstance()
  +getInt(key,def) +getDouble(key,def) +getString(key,def) +getList(key) +reload() +overlay(path)
EventLog <<Singleton>>: -{static}instance -entries:List<String> -logFile:Path -EventLog() |
  +{static}getInstance() +log(level:LogLevel,component:String,msg:String) +getEntries() +clear()
InvalidConfigException (extends RuntimeException)
LogLevel <<enum>>: INFO, WARN, ERROR

RELATIONSHIPS
Generalization:
  Server, Workstation, Router, IoTDevice -> NetworkAsset
  LowAlert, HighAlert, CriticalAlert -> Alert
  Admin, SecurityAnalyst, Viewer -> User
  PortScanGenerator, BruteForceGenerator, DosFloodGenerator, DataTransferGenerator -> AttackGenerator
  SignatureDetector, RateThresholdDetector, PortScanDetector, AnomalyDetector, ThreatIntelDetector,
  BeaconingDetector, DataExfilDetector, LateralMovementDetector, FloodDetector -> Detector
  SqliteAlertRepository, InMemoryAlertRepository -> AlertRepository
  SqliteFlowRepository, InMemoryFlowRepository -> FlowRepository
  InMemoryRecordStore -> RecordStore
  SmtpMailer -> Mailer

Realization of AlertListener:
  RiskScorer, IncidentManager, AlertLogger, StreamBroadcaster, PersistenceService,
  SiemCorrelator, ContainmentService, NotificationService, MlFlowScorer

Realization of AlertGate:
  AlertQualityGate

Realization of AlertUpdateListener:
  AlertRegistry

Realization of RecordStore:
  InMemoryRecordStore

Realization of Mailer:
  SmtpMailer

Composition (diamond at whole):
  Network -> NetworkAsset (0..*, assets)
  Network -> Link (0..*, links)
  AnomalyDetector -> RunningStats (stats)
  SOC -> DetectionEngine
  IncidentManager -> Incident (0..*)
  ResponsePlan -> BackboneResult
  ResponsePlan -> AssignmentResult
  WebServer -> ApiRoutes
  WebServer -> StreamBroadcaster
  Database -> SqliteTable (8 tables)

Aggregation:
  TrafficSimulator -> AttackGenerator (1..*)
  TrafficSimulator -> HostProfile
  DetectionEngine -> Detector (1..*)
  AlertBus -> AlertListener (0..*)
  AlertBus -> AlertGate (0..1)
  SOC -> AnalystTeam (0..*)
  Incident -> Alert (1..*)
  MlFlowScorer -> AnomalyModel (0..1)
  ThreatIntelDetector -> ThreatIntel
  ContainmentService -> ContainmentRecord (0..*)
  NotificationService -> NotificationRecord (0..*)
  AuditLog -> AuditRecord (0..*)
  WriteBehindQueue -> Object (bounded)
  ComplianceService -> PersistenceService, AuditLog, NotificationService, ContainmentService, EvidenceExporter
  DetectionEngine -> Consumer<NetworkEvent> (0..*, event observers)

Association:
  Link -> NetworkAsset (2)
  TrafficSimulator -> AttackRecord (groundTruth)
  DetectionEngine -> AlertBus
  DetectionEngine -> FlowRecorder (0..*, event observers)
  DetectionEngine -> AlertGate (0..1)
  DetectionEngine -> Predicate<NetworkEvent> (admission)
  RiskScorer -> Network
  AuthService -> User
  IncidentResponseFacade -> Network, TrafficSimulator, DetectionEngine, AlertBus, RiskScorer,
    IncidentManager, SOC, AuthService, BackbonePlanner, AssignmentPlanner, ReportGenerator,
    User (currentUser), FlowRecorder, PersistenceService, AuditLog, MlFlowScorer, SiemCorrelator,
    ContainmentService, NotificationService, EvidenceExporter, ComplianceService, IntelService,
    ScenarioService, ImportService, ExportService
  WebServer -> IncidentResponseFacade
  ApiRoutes -> IncidentResponseFacade
  ApiRoutes -> StreamBroadcaster
  DetectorFactory -> Detector (creates)

Dependencies:
  <<creates>>: AssetFactory -> NetworkAsset, AlertFactory -> Alert, TopologyLoader -> Network,
    DetectorFactory -> Detector, TrafficSimulator -> NetworkEvent, AttackGenerator -> NetworkEvent,
    BackbonePlanner -> BackboneResult, AssignmentPlanner -> AssignmentResult, ApiRoutes -> Dtos,
    EvidenceExporter -> Bundle
  <<reads>>: TrafficSimulator -> Network, KillChainRules -> config, SuppressionRules -> config
  <<throws>>: AuthService -> AuthenticationException, ConfigManager -> InvalidConfigException
  <<use>>: PersistenceService -> WriteBehindQueue, FlowRepository, AlertRepository, Database;
    FlowRepository -> FlowRecord; AlertRepository -> AlertRecord; ComplianceService -> PersistenceStatus;
    SiemCorrelator -> AlertBus, AlertFactory; ContainmentService -> NetworkEvent, ConfigManager, ContainmentSafeguards;
    EvidenceExporter -> FlowRecord, AlertRecord, Incident; ZeekConnLogParser -> ZeekImportResult, FlowRecord;
    MlFlowScorer -> FeatureVector, FlowFeatures; AnomalyModel -> KMeans, FlowFeatures;
    ImportService -> ZeekConnLogParser, ImportLabels; ExportService -> Table.
