PROJECT CONTEXT
Course CT-263 Object-Oriented Analysis and Design (CCA live demo + CCP report).
System: "Network Threat Detection & Cyber Security Monitoring System".
Java 17 backend with a React web front end. No Swing. Simulated network, rule-based detection (no ML),
alerts, risk scores, response planner (Kruskal backbone + DP task assignment), incident report.
Same codebase as a DAA project; the OOAD report centres on UML + patterns + demo.
Brief rule: report diagrams must match the lab demo exactly.
Report must contain the 8 UML diagrams (use case, activity, class, object, component,
sequence, communication, deployment).
Tool: Modelio 5.4. The class model has 69 elements after the move from Swing to web.

STATUS
Done: backend (domain, simulation, detection, service, response, util) with tests, DAA planners,
class, component, use case and activity diagrams drawn (need the Swing to web edits).
To do: web package (REST + SSE), web-client (React), then the object, sequence, communication and
deployment diagrams from a real run, then the reports.

RULES AND DECISIONS
- Packages: domain, simulation, detection, service, response, util, web. No Swing or AWT anywhere.
- Dependency rule:
  - domain imports nothing from other project packages.
  - simulation and detection depend only on domain and util.
  - response depends only on domain.
  - service depends on domain, detection, simulation, response, util.
  - web depends only on service (IncidentResponseFacade), domain (read only) and detection.AlertListener.
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

PACKAGE detection (10)
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
  -lastAlertAt:Map<String,Instant> | +start() +stop() +addDetector(d) +reset() -process(e:NetworkEvent)

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

PACKAGE web (4)  - no detection or algorithm code; talks only to IncidentResponseFacade and domain
WebServer: -app:Javalin -facade:IncidentResponseFacade -lock:ReentrantLock | +start(port:int):void +stop():void +port():int
ApiRoutes: -facade:IncidentResponseFacade -broadcaster:StreamBroadcaster -lock:ReentrantLock | +register(app:Javalin):void
StreamBroadcaster (implements AlertListener): -clients:Set<SseClient> -recent:Deque<Alert> | +onAlert(a:Alert):void
  +addClient(c:SseClient):void +removeClient(c:SseClient):void +getRecentAlerts(limit:int):List<Alert> +broadcastState():void
Dtos: nested records only (AssetDto, LinkDto, AlertDto, IncidentDto, PlanDto, StateDto), no behaviour

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