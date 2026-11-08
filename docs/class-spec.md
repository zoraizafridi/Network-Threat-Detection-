PROJECT CONTEXT
Course CT-263 Object-Oriented Analysis and Design (CCA live demo + CCP report).
System: "Network Threat Detection & Cyber Security Monitoring System".
Java 17 backend with a React web front end. No Swing. Simulated network, rule-based detection (no ML),
alerts, risk scores, response planner (Kruskal backbone + DP task assignment), incident report.
Same codebase as a DAA project; the OOAD report centres on UML + patterns + demo.
Brief rule: report diagrams must match the lab demo exactly.
Report must contain the 8 UML diagrams (use case, activity, class, object, component,
sequence, communication, deployment).
Tool: Modelio 5.4. The class model has 105 elements after the move from Swing to web and the
monitoring phases.

STATUS
Done: backend (domain, simulation, detection, service, response, util, flows, persistence, security,
zeek, intel, ml, correlation, containment, notify, forensics, compliance, bench) with tests, DAA
planners, class, component, use case and activity diagrams drawn.
To do: the object, sequence, communication and deployment diagrams from a real run, then the reports.

RULES AND DECISIONS
- Packages: domain, simulation, detection, service, response, util, web, flows, persistence, security,
  zeek, intel, ml, correlation, containment, notify, forensics, compliance, bench. No Swing or AWT.
- Dependency rule:
  - domain imports nothing from other project packages.
  - simulation and detection depend only on domain and util.
  - response depends only on domain.
  - service depends on domain, detection, simulation, response, util.
  - web depends only on service (IncidentResponseFacade), domain (read only), detection.AlertListener
    and detection.AlertGate. It reads the newer services through facade getters and never constructs
    them, so the wiring stays in one place.
  - The entry class Main may depend on any package and passes port and seed to web.
- Show a relationship as an arrow OR an attribute, never both.
- Omit getters/setters except where listed. Mark abstract classes and static members.
- NetworkEvent is immutable with NO "malicious" field (detectors never see ground truth).
- Patterns, only these 5: Strategy (Detector + 4 subclasses), Observer (AlertBus/AlertListener),
  Factory (AssetFactory, AlertFactory, DetectorFactory), Singleton (ConfigManager, EventLog),
  Facade (IncidentResponseFacade).
- Threading: simulator thread -> BlockingQueue -> detection thread -> AlertBus -> StreamBroadcaster
  -> SSE to browsers. Web handlers call the facade under one lock.
- 4 detectors: SignatureDetector (bad IP/port/payload), RateThresholdDetector (failed logins in
  a window), PortScanDetector (distinct ports/hosts in a window), AnomalyDetector (Welford running
  mean/stddev per host, z-score > 3, warm-up, no baseline update on flagged values).
- Alert cooldown/de-duplication in DetectionEngine. All thresholds come from ConfigManager.
- The web package and the client contain no detection, risk, Kruskal or DP logic.
- The newer capabilities are seams, not rewrites: AlertGate is one method, the admission predicate is
  one Predicate, the quality gate is a decorator of the alert path, and the four NDR detectors extend
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
LogLevel: INFO, WARN, ERROR               (package util)

PACKAGE domain (32 elements incl. 7 enums)
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
NetworkEvent (all fields final): -id:long -timestamp:Instant -sourceIp:String -destIp:String -port:int
  -bytes:long -type:EventType -success:boolean -payload:String
Alert {abstract}: -id:String -timestamp:Instant -severity:Severity -attackType:AttackType
  -sourceIp:String -targetIp:String -detectorName:String -description:String | +{abstract}getRiskIncrement():double
LowAlert, HighAlert, CriticalAlert: +getRiskIncrement():double
AlertFactory <<Factory>>: +create(sev:Severity,type:AttackType,src:String,dst:String,detector:String,desc:String,time:Instant):Alert
User {abstract}: -username:String -passwordHash:String | +checkPassword(raw:String):boolean
  +{abstract}canLaunchAttack() +{abstract}canRunPlanner() +{abstract}canConfigure() +{abstract}canManageUsers(): boolean
Admin (all true), SecurityAnalyst (launch/plan/export true; configure/manage false), Viewer (all false)
AnalystTeam: -id:String -name:String -skills:Set<String> -capacity:int -available:boolean | +canHandle(t:MitigationTask):boolean
MitigationTask: -id:String -target:NetworkAsset -value:int -cost:int -requiredSkill:String -daysUnpatched:int
  (value is the base value; the facade computes the final decayed value once, before the DP,
   as value * (1 + decay.rate * daysUnpatched))
AuthenticationException (extends Exception)
BackboneResult: -chosenLinks:List<Link> -totalWeight:double -connected:boolean -unreachable:List<NetworkAsset>
AssignmentResult: -assignments:Map<AnalystTeam,List<MitigationTask>> -totalValue:int -excluded:List<MitigationTask> -stateCount:long
ResponsePlan: has composition to BackboneResult (backbone) and AssignmentResult (assignment)

PACKAGE simulation (8)
TrafficSimulator: -clock:Clock -random:Random -queue:BlockingQueue<NetworkEvent> -running:AtomicBoolean
  -autoMode:boolean | +start() +stop() +reset() +setAutoMode(on:boolean)
  +injectAttack(type:AttackType,srcIp:String,dstIp:String):void +generateNormalEvent():NetworkEvent
  +getEventQueue():BlockingQueue<NetworkEvent>
HostProfile: -meanBytes:double -stdBytes:double -commonPorts:List<Integer> -eventsPerSecond:double
AttackGenerator {abstract}: +{abstract}generate(src:String,dst:String,now:Instant,rnd:Random):List<NetworkEvent>
PortScanGenerator, BruteForceGenerator, DosFloodGenerator, DataTransferGenerator: same generate()
AttackRecord (tests only): -type:AttackType -source:String -target:String -startTime:Instant

PACKAGE detection (16)
AlertListener <<interface, Observer>>: +onAlert(a:Alert):void
AlertBus <<Observer>>: +subscribe(l) +unsubscribe(l) +publish(a:Alert) (CopyOnWriteArrayList; one failing listener must not break others)
Detector {abstract} <<Strategy>>: #name:String | +{abstract}analyze(e:NetworkEvent):Optional<Alert> +getName():String +reset():void
SignatureDetector: -badIps:Set<String> -badPorts:Set<Integer> -payloadPatterns:List<Pattern>
RateThresholdDetector: -windowSeconds:int -maxFailures:int -failuresBySource:Map<String,Deque<Instant>> | -prune(q,now)
PortScanDetector: -windowSeconds:int -maxDistinctPorts:int -maxDistinctHosts:int -touches:Map<String,Deque<Touch>>
AnomalyDetector: -zThreshold:double -warmupCount:int (stats via composition to RunningStats, role "stats")
RunningStats: -count:long -mean:double -m2:double | +update(x:double) +getStdDev():double +zScore(x:double):double
DetectorFactory <<Factory>>: +create(name:String):Detector +createAll():List<Detector>
DetectionEngine: -queue:BlockingQueue<NetworkEvent> -worker:Thread -running:AtomicBoolean -cooldownSeconds:int
  -lastAlertAt:Map<String,Instant> -eventObservers:List<Consumer<NetworkEvent>> -alertGate:AlertGate
  -admission:Predicate<NetworkEvent> -droppedEvents:AtomicLong |
  +start() +stop() +addDetector(d) +reset() +addEventObserver(o) +setAlertGate(g) +setAdmission(p)
  +getDroppedEvents():long -process(e:NetworkEvent) -notifyObservers(e)
  (the admission predicate is checked first and a refused event is counted instead of analysed; the
   gate runs before the per-source cooldown is recorded, so a suppressed alert costs no cooldown)
AlertGate <<interface>>: +allow(a:Alert):boolean   [ALLOW_ALL is the default implementation]
AlertQualityGate (implements AlertGate): -dedupeEnabled:boolean -windowSeconds:int
  -minimumSeverity:Severity -maxKeys:int -seen:Map<String,Instant> |
  +allow(a) +stats():Stats +reset()   [Stats is a nested record of the counters]
BeaconingDetector (extends Detector): -minSamples:int -jitterTolerance:double -minIntervalMillis:long
  -maxIntervalMillis:long -maxTracked:int -cooldownMillis:long -series:Map<String,Series>
DataExfilDetector (extends Detector): -windowMillis:long -maxBytes:long -maxTracked:int
  -cooldownMillis:long -internalPrefixes:List<String> -windows:Map<String,Window>
LateralMovementDetector (extends Detector): -windowMillis:long -maxHosts:int -maxTracked:int
  -cooldownMillis:long -adminPorts:Set<Integer> -sources:Map<String,Source>
ThreatIntelDetector (extends Detector): -intel:ThreatIntel -enabled:boolean | +attackTypeFor(t:EventType):AttackType
  (DetectorFactory.createNdr() builds the four; createAll() still returns the original four)

PACKAGE service (8)
IncidentResponseFacade <<Facade>>: +login(u:String,p:String):User +start() +stop() +reset() +setAutoMode(on:boolean)
  +isRunning():boolean +isAutoMode():boolean
  +launchAttack(type:AttackType,src:String,dst:String) +runResponse():ResponsePlan +generateReport():String
  +exportReport(path:String) +addAlertListener(l:AlertListener) +getNetwork():Network +getIncidents():List<Incident>
  (runResponse builds one MitigationTask per COMPROMISED or SUSPICIOUS host:
   value = round(riskScore * criticality), cost = effort hours by asset type
   (config keys task.cost.server, task.cost.workstation, task.cost.router, task.cost.iot),
   daysUnpatched from config key task.days.unpatched.default;
   only tasks on hosts in the SOC's component go to the DP)
  (the facade also owns the newer services and exposes each through one getter: getFlowRecorder,
   getMlFlowScorer, getPersistenceService, getAuditLog, getAlertQualityGate, getSiemCorrelator,
   getContainmentService, getNotificationService, getEvidenceExporter, getComplianceService)
  (wiring, in the constructor: detectionEngine.addEventObserver(flowRecorder);
   flowRecorder.addCloseListener(mlFlowScorer::onFlow);
   flowRecorder.addCloseListener(persistenceService::recordFlow);
   detectionEngine.setAlertGate(alertQualityGate);
   detectionEngine.setAdmission(containmentService::admit), only when enforcement is on)
RiskScorer (implements AlertListener): -cap:double -compromiseThreshold:double -decayPerTick:double |
  +onAlert(a) +decay() +reset() -markAdjacentLinks(asset:NetworkAsset)
AlertLogger (implements AlertListener): +onAlert(a)   [writes to EventLog]
Incident: -id:String -sourceIp:String -openedAt:Instant -status:IncidentStatus |
  +addAlert(a) +getHighestSeverity():Severity +close()
  +getId():String +getSourceIp():String +getStatus():IncidentStatus +getOpenedAt():Instant
  +getAlerts():List<Alert> (read-only copy)
IncidentManager (implements AlertListener): -correlationWindowSeconds:int | +onAlert(a) +getIncidents() +reset()
SOC: +addTeam(t:AnalystTeam) +getAvailableTeams():List<AnalystTeam>
AuthService: +login(username:String,password:String):User   [throws AuthenticationException]
  (registers three accounts from config: admin as Admin, analyst as SecurityAnalyst, viewer as Viewer;
   keys auth.defaultUsername/Password, auth.analystUsername/Password, auth.viewerUsername/Password)
ReportGenerator: +generate(incidents:List<Incident>,network:Network,plan:ResponsePlan):String +export(report:String,path:String):void

PACKAGE response (3)
BackbonePlanner: +plan(network:Network):BackboneResult -edgeWeight(l:Link):double
  (edgeWeight returns baseCost only; only links not COMPROMISED are candidates;
   sort by cost asc, then combined endpoint riskScore desc, then link id asc;
   SOC host id read from ConfigManager key soc.host.id, default the first ROUTER asset when the key is empty;
   unreachable = hosts outside the SOC's component, by name)
UnionFind: -parent:int[] -rank:int[] | +find(x:int):int (path compression) +union(a:int,b:int):boolean (by rank)
AssignmentPlanner: +plan(tasks:List<MitigationTask>,teams:List<AnalystTeam>):AssignmentResult -buildTable(...) -backtrack(...)
  (exact multiple knapsack DP, task weight = cost, value = value, team capacity = effort hours;
   tasks heavier than every team go to excluded; skills and canHandle are not used by the DP;
   guard: ConfigManager key dp.max.states)

PACKAGE flows (3)  - no detection logic; consumes the same NetworkEvents and only reads them back
FlowRecord <<record>>: id:String srcIp:String dstIp:String srcPort:int dstPort:int protocol:String
  bytesOut:long bytesIn:long packets:long startTime:Instant endTime:Instant flags:List<String>
  label:String simulated:boolean ended:boolean | +durationMs():long
FlowQuery <<record>>: srcIp:String dstIp:String port:Integer from:Instant to:Instant limit:int
  includeActive:boolean | +{static}all(limit:int):FlowQuery -matches(f:FlowRecord):boolean
FlowRecorder (implements Consumer<NetworkEvent>): -enabled:boolean -idleTimeoutMillis -maxRecords
  -maxActiveFlows -retentionMillis -udpPorts:Set<Integer> -labelRules:List<LabelRule>
  -active:Map<String,Mutable> -closed:Deque<FlowRecord> -sequence:long -watermark:Instant |
  +accept(e:NetworkEvent):void +query(q:FlowQuery):List<FlowRecord> +reset():void +isEnabled():boolean
  -close(key:String):void -expireIdle():void -purgeExpired():void -{static}ephemeralPort(...):int
  (aggregates on the five tuple, closes after the idle timeout, bounded closed ring, retention purge,
   payload to label rules from ConfigManager; synchronized because the detector thread writes and
   the HTTP thread reads)

PACKAGE persistence (9)  - the only package that touches SQL; nothing on the detection path waits on it
PersistenceSettings <<record>>: enabled:boolean databasePath:Path queueCapacity:int batchSize:int
  flushIntervalMillis:long retentionMinutes:int sweepMinutes:int |
  +{static}from(c:ConfigManager) +{static}disabled() +withEnabled(b) +withDatabasePath(p)
  +withQueueCapacity(n) +withBatchSize(n) +withRetentionMinutes(n)
PersistenceStatus <<record>>: enabled:boolean databasePath:String flowRows:int alertRows:int
  queuedRows:long droppedRows:long writtenRows:long lastFlushAt:String lastError:String |
  +{static}off(path:String):PersistenceStatus
PersistenceService (implements AlertListener, AutoCloseable): -settings:PersistenceSettings
  -database:Database -flows:FlowRepository -alerts:AlertRepository -flowQueue -alertQueue
  -sweeper:ScheduledExecutorService -lastSwept:AtomicInteger |
  +recordFlow(r:FlowRecord) +onAlert(a:Alert) +storedFlows(limit):List<FlowRecord>
  +storedAlerts(limit):List<AlertRecord> +importFlows(l):int +importAlerts(l):int +status()
  +sweepNow():int +lastSweptRows():int +flush(timeoutMillis):boolean +close()
Database: -writer:Connection -reader:Connection -file:Path | +writer() +reader() +file() +close()
  (SQLite in WAL mode, one writer and one reader connection, PRAGMA user_version for the schema)
FlowRepository: +insertBatch(l) +recent(limit):List<FlowRecord> +deleteBefore(cutoff):int +count():int
AlertRepository: +insertBatch(l) +recent(limit):List<AlertRecord> +deleteBefore(cutoff):int +count():int
AlertRecord <<record>>: id:String timestamp:Instant severity:String attackType:String sourceIp:String
  targetIp:String detector:String description:String simulated:boolean |
  +{static}from(a:Alert):AlertRecord   (strings on purpose: a row records what was raised)
WriteBehindQueue<T> {package}: -name:String -capacity:int -batchSize:int -pending:Deque<T>
  -written:AtomicLong -dropped:AtomicLong -lastFlush:AtomicReference<Instant>
  -lastError:AtomicReference<String> -writing:AtomicBoolean -worker:Thread |
  +offer(item):boolean +flush(timeoutMillis):boolean +queued() +written() +dropped() +lastError() +close()
  (bounded, one daemon worker, a drained batch counts as in flight until it is committed, a failing
   sink is counted, described and survived)
PersistenceException (extends RuntimeException)

PACKAGE security (1)
AuditLog: -enabled:boolean -maxRecords:int -entries:Deque<Entry> -sequence:long -denied:long
  -failed:long | +record(actor,action,target,outcome,detail) +recent(limit):List<Entry> +size():int
  +deniedCount():long +failedCount():long +isEnabled() +getMaxRecords():int +reset()
  Outcome <<enum>>: ALLOWED, DENIED, FAILED
  Entry <<record>>: sequence:long timestamp:Instant actor:String action:String target:String
    outcome:String detail:String   (a null actor becomes anonymous, a null outcome becomes allowed)

PACKAGE zeek (2)  - offline import only; nothing here runs on the live path
ZeekConnLogParser: -maxFlows:int | +parse(file:Path):ZeekImportResult
  +parse(content:String,source:String):ZeekImportResult   (reads the #fields header, never a fixed order)
ZeekImportResult <<record>>: source:String linesRead:long flowsParsed:long skipped:long
  firstTimestamp:Instant lastTimestamp:Instant hosts:Set<String> problems:List<String>
  records:List<FlowRecord> | +summary():String

PACKAGE intel (2)
IntelEntry <<record>>: cidr:String label:String severity:Severity source:String
ThreatIntel: -entries:List<IntelEntry> -skipped:long | +{static}fromConfig()
  +{static}load(location:String,fallbackSeverity):ThreatIntel
  +{static}parse(text:String,source:String,fallbackSeverity):ThreatIntel
  +match(ip:String):Optional<IntelEntry> +size():int +skippedLines():long +entries():List<IntelEntry>

PACKAGE ml (5)  - pure Java, no third party machine learning library
FlowFeatures <<record>>: values:double[] | SIZE:int = 6 | +value(i):double
FeatureVector: +{static}of(f:FlowRecord):FlowFeatures   (six log-scaled features)
KMeans: +{static}fit(points,k,maxIterations,seed):Result +{static}nearestDistance(p,centroids):double
  Result <<record>>: centroids:double[][] assignments:int[] inertia:double iterations:int
  (k-means++ seeding, so a fixed seed gives the same model twice)
AnomalyModel: -mean:double[] -deviation:double[] -centroids:double[][] -scale:double -samples:int |
  +{static}train(samples,k,maxIterations,seed):AnomalyModel +score(f):double +distance(f):double
  +clusters():int +samples():int +scale():double   (score is clamped to 0..1, scale is the p95 distance)
MlFlowScorer (AutoCloseable): -alertBus:AlertBus -gate:AlertGate -enabled -k -minSamples
  -retrainSeconds -threshold -maxTrainFlows -seed -alertSeverity -cooldownMillis -maxTrackedSources
  -training:Deque<FlowFeatures> -model:AnomalyModel -dirty:AtomicBoolean -retrainer |
  +onFlow(f:FlowRecord) +train():boolean +score(f):double +status():Status +sampleCount():int
  +isEnabled() +reset() +close()   [Status is a nested record; state is disabled, cold, training or ready]

PACKAGE correlation (1)
SiemCorrelator (implements AlertListener): -bus:AlertBus -enabled -minSignals -windowSeconds
  -cooldownSeconds -maxSources -escalateSeverity -signals:Map<String,Source> -signalCount:long |
  +onAlert(a:Alert) +status():Status +reset()
  (ignores alerts whose detector name is its own, so it cannot feed itself)

PACKAGE containment (1)
ContainmentService (implements AlertListener): -clock:Clock -enabled -auto -enforce -autoMinutes
  -maxDurationMinutes -maxBlocked -autoSeverity -blocked:Map<String,Action> |
  +admit(e:NetworkEvent):boolean +contain(ip,minutes,reason,actor):Action +release(ip):boolean
  +isBlocked(ip):boolean +active():List<Action> +onAlert(a) +status():Status +reset()
  Action <<record, nested>>: ip:String blockedAt:Instant expiresAt:Instant reason:String actor:String
    automatic:boolean
  Status <<record, nested>>: enabled:boolean auto:boolean enforce:boolean blocked:int droppedEvents:long
    automaticActions:long expiredActions:long

PACKAGE notify (1)
NotificationService (implements AlertListener): -enabled -minimumSeverity:Severity -maxOutbox:int
  -webhookUrl:String -maxInFlight:int -client:HttpClient -outbox:Deque<Notification>
  -recorded:AtomicLong -webhookSent -webhookFailed -dropped:AtomicLong -inFlight:AtomicInteger |
  +onAlert(a:Alert) +recent(limit):List<Notification> +status():Status +reset()
  Notification <<record, nested>>: id:String timestamp:Instant severity:Severity attackType:String
  sourceIp:String targetIp:String detector:String description:String

PACKAGE forensics (1)
EvidenceExporter: -enabled:boolean -directory:Path -maxFlows:int -maxAlerts:int |
  +export(actor,flows:List<FlowRecord>,alerts:List<AlertRecord>,audit:List<AuditLog.Entry>,
   incidents:List<Incident>):Bundle +isEnabled():boolean +directory():Path
  Bundle <<record>>: directory:String createdAt:String files:int bytes:long manifestSha256:String actor:String
  (each export is a timestamped directory with the records plus a manifest of the SHA-256 per file)

PACKAGE compliance (1)
ComplianceService: -persistence -audit:AuditLog -notifications -containment -forensics:EvidenceExporter
  -config:ConfigManager | +summary():Summary +retentionCutoff():String +configuredAuditCap():int
  Summary <<record>>: storeEnabled databasePath storedFlows storedAlerts droppedRows retentionMinutes
   sweepMinutes auditCapacity auditRecords auditDenied auditFailed notificationsEnabled
   notificationBacklog containmentEnabled containedSources forensicsEnabled evidenceDirectory

PACKAGE bench (1)  - measures, never asserts on timing
Benchmarks: +{static}run(scale:int):List<Result> +{static}report(results):String
  Result <<record>>: name:String operations:int elapsedNanos:long | +microsPerOperation():double
   +operationsPerSecond():double +line():String

PACKAGE web (5)  - no detection or algorithm code; talks only to IncidentResponseFacade and domain
WebServer: -app:Javalin -facade:IncidentResponseFacade -lock:ReentrantLock | +start(port:int):void +stop():void +port():int
ApiRoutes: -facade:IncidentResponseFacade -broadcaster:StreamBroadcaster -lock:ReentrantLock | +register(app:Javalin):void
LoginThrottle: -attempts:Map<String,Deque<Instant>> | +allow(key:String):boolean +retryAfterSeconds(key:String):long
  (five failures per username and address inside five minutes, then 429 with Retry-After)
StreamBroadcaster (implements AlertListener): -clients:Set<SseClient> -recent:Deque<Alert> | +onAlert(a:Alert):void
  +addClient(c:SseClient):void +removeClient(c:SseClient):void +getRecentAlerts(limit:int):List<Alert> +broadcastState():void
Dtos: nested records only (AssetDto, LinkDto, AlertDto, IncidentDto, FlowDto, PlanDto, StateDto), no behaviour

PACKAGE util (4)
ConfigManager <<Singleton>>: -{static}instance -props:Properties -ConfigManager() | +{static}getInstance() +load(path)
  +getInt(key,def) +getDouble(key,def) +getString(key,def) +getList(key)   [throws InvalidConfigException]
EventLog <<Singleton>>: -{static}instance -entries:List<String> -logFile:Path -EventLog() |
  +{static}getInstance() +log(level:LogLevel,component:String,msg:String) +getEntries() +clear()
InvalidConfigException (extends RuntimeException)

RELATIONSHIPS
Generalization: Server/Workstation/Router/IoTDevice->NetworkAsset; Low/High/CriticalAlert->Alert;
  Admin/SecurityAnalyst/Viewer->User; 4 generators->AttackGenerator; 4 detectors->Detector.
Composition (diamond at whole): Network->NetworkAsset(0..*,assets), Network->Link(0..*,links),
  AnomalyDetector->RunningStats, SOC->DetectionEngine, IncidentManager->Incident,
  ResponsePlan->BackboneResult, ResponsePlan->AssignmentResult,
  WebServer->ApiRoutes, WebServer->StreamBroadcaster.
Aggregation: TrafficSimulator->AttackGenerator(1..*), TrafficSimulator->HostProfile, DetectionEngine->Detector(1..*),
  AlertBus->AlertListener, SOC->AnalystTeam, Incident->Alert(1..*).
Association: Link->NetworkAsset(2), TrafficSimulator->AttackRecord(groundTruth), DetectionEngine->AlertBus,
  DetectionEngine->FlowRecorder(0..*, event observers), IncidentResponseFacade->FlowRecorder,
  RiskScorer->Network, AuthService->User,
  IncidentResponseFacade -> Network, TrafficSimulator, DetectionEngine, AlertBus, RiskScorer, IncidentManager,
  SOC, AuthService, BackbonePlanner, AssignmentPlanner, ReportGenerator, User(currentUser);
  WebServer -> IncidentResponseFacade; ApiRoutes -> IncidentResponseFacade; ApiRoutes -> StreamBroadcaster.
Realization of AlertListener: RiskScorer, IncidentManager, AlertLogger, StreamBroadcaster.
Dependencies: <<creates>>: AssetFactory->NetworkAsset, AlertFactory->Alert, TopologyLoader->Network,
  DetectorFactory->Detector, TrafficSimulator->NetworkEvent, AttackGenerator->NetworkEvent,
  BackbonePlanner->BackboneResult, AssignmentPlanner->AssignmentResult, ApiRoutes->Dtos.
  <<reads>> TrafficSimulator->Network. <<throws>> AuthService->AuthenticationException,
  ConfigManager->InvalidConfigException. <<use>> everything else (Detector->NetworkEvent/Alert/
  AlertFactory/ConfigManager, DetectionEngine->NetworkEvent, AlertBus->Alert, AlertLogger->EventLog,
  BackbonePlanner->UnionFind/Network, AssignmentPlanner->MitigationTask/AnalystTeam,
  ReportGenerator->Network/Incident/ResponsePlan, Facade->ResponsePlan/Incident,
  ApiRoutes->Alert/Network/ResponsePlan/Incident, AnalystTeam->MitigationTask).
ConfigManager <<use>> links from TrafficSimulator, DetectionEngine, RiskScorer, IncidentManager exist in the model
  but are hidden on diagrams for readability.

PHASE 2 TO 13 LINKS (add these edges before redrawing)
Aggregation: AlertBus->AlertGate(1), DetectionEngine->Consumer<NetworkEvent>(0..*, event observers),
  MlFlowScorer->AnomalyModel(0..1), ThreatIntelDetector->ThreatIntel,
  ContainmentService->Action(0..*), NotificationService->Notification(0..*),
  AuditLog->Entry(0..*), WriteBehindQueue->Object(bounded), ComplianceService->the five services it reports.
Realization of AlertListener: PersistenceService, SiemCorrelator, ContainmentService, NotificationService.
Realization of AlertGate: AlertQualityGate (ALLOW_ALL is a constant, not a class in the model).
Generalization: BeaconingDetector, DataExfilDetector, LateralMovementDetector, ThreatIntelDetector -> Detector.
Association: DetectionEngine->AlertGate(0..1), DetectionEngine->Predicate<NetworkEvent>(admission),
  DetectorFactory->ThreatIntelDetector(creates), IncidentResponseFacade->PersistenceService/AuditLog/
  MlFlowScorer/SiemCorrelator/ContainmentService/NotificationService/EvidenceExporter/ComplianceService,
  ApiRoutes->the same services through facade getters, Main->ZeekConnLogParser and Benchmarks.
<<use>>: PersistenceService->WriteBehindQueue/FlowRepository/AlertRepository/Database,
  FlowRepository->FlowRecord, AlertRepository->AlertRecord, ComplianceService->PersistenceStatus,
  SiemCorrelator->AlertBus/AlertFactory, ContainmentService->NetworkEvent/ConfigManager,
  EvidenceExporter->FlowRecord/AlertRecord/Incident, ZeekConnLogParser->ZeekImportResult/FlowRecord,
  MlFlowScorer->FeatureVector/FlowFeatures, AnomalyModel->KMeans/FlowFeatures.
No composition is claimed across the queues: a facade owns the services, a service owns its queue.