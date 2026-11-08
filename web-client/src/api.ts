import type { FeedAlert } from "./alerts";
import { useApp } from "./store";
import type { Asset, ContainedAddress, FlowRow, IncidentRow, NetLink, PlanBody, SocTeam } from "./types";

export class HttpStatusError extends Error {
  status: number;

  constructor(status: number) {
    super(String(status));
    this.status = status;
  }
}

export async function request(path: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  const method = (init?.method ?? "GET").toUpperCase();
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (method !== "GET" && method !== "HEAD" && !headers.has("X-CSRF-Token")) {
    const token = csrfToken();
    if (token) {
      headers.set("X-CSRF-Token", token);
    }
  }
  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "same-origin",
  });
  if (response.status === 401 && path !== "/api/login") {
    useApp.getState().applyHttpStatus(401);
  }
  if (!response.ok) {
    throw new HttpStatusError(response.status);
  }
  return response;
}

function csrfToken(): string | null {
  if (typeof document === "undefined") {
    return null;
  }
  const match = document.cookie.match(/(?:^|;\s*)csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

export async function readJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await request(path, init);
  return (await response.json()) as T;
}

export interface DemoAccount {
  username: string;
  role: string;
  password: string;
}

export interface DemoInfo {
  demoMode: boolean;
  notice?: string;
  accounts?: DemoAccount[];
}

let demoRequest: Promise<DemoInfo> | null = null;

export function loadDemo(): Promise<DemoInfo> {
  if (!demoRequest) {
    demoRequest = readJson<DemoInfo>("/api/demo").catch(() => ({ demoMode: false }));
  }
  return demoRequest;
}

export interface StateBody {
  running: boolean;
  autoMode: boolean;
  user: { username: string; role: string };
  alertCount: number;
  incidentCount: number;
}

export function applyState(body: StateBody): void {
  const store = useApp.getState();
  if (body.user?.username) {
    store.setUser({ username: body.user.username, role: body.user.role });
  }
  store.setSimulation(body.running, body.autoMode, body.alertCount, body.incidentCount);
}

export async function loadState(): Promise<StateBody> {
  const body = await readJson<StateBody>("/api/state");
  applyState(body);
  return body;
}

export async function loadNetwork(): Promise<void> {
  const body = await readJson<{ assets: Asset[]; links: NetLink[]; teams?: SocTeam[]; contained?: ContainedAddress[] }>(
    "/api/network",
  );
  useApp.getState().setNetwork(body.assets, body.links, body.teams ?? [], (body.contained ?? []).map((entry) => entry.ip));
}

export async function loadAlerts(): Promise<void> {
  const body = await readJson<FeedAlert[]>("/api/alerts?limit=500");
  useApp.getState().setAlerts(body);
}

export interface AlertQualityBody {
  raw: number;
  delivered: number;
  ratio: number;
  folded: number;
  suppressed: number;
  belowFloor: number;
  ruleSuppressed: number;
  stormSuppressed: number;
  duplicates: number;
  dedupeEnabled: boolean;
  windowSeconds: number;
  minimumSeverity: string;
  maxPerMinute: number;
  rules: number;
  tracked: number;
}

export async function loadAlertQuality(): Promise<AlertQualityBody> {
  return readJson<AlertQualityBody>("/api/alert-quality");
}

export interface ProposedRule {
  detector: string;
  attackType: string;
  sourceIp: string;
  targetIp: string;
  maxSeverity: string;
  note: string;
  enabled?: boolean;
}

export interface AlertStatusBody {
  alert: FeedAlert;
  proposedRule?: ProposedRule;
}

export async function setAlertStatus(id: string, status: string): Promise<AlertStatusBody> {
  return readJson<AlertStatusBody>(`/api/alerts/${encodeURIComponent(id)}/status`, {
    method: "POST",
    body: JSON.stringify({ status }),
  });
}

export interface SuppressionRule extends ProposedRule {
  id: string;
  createdBy: string;
  createdAt: string;
  enabled: boolean;
  describe: string;
}

export interface SuppressionBody {
  enabled: boolean;
  file: string;
  count: number;
  rules: SuppressionRule[];
}

export async function loadSuppressionRules(): Promise<SuppressionBody> {
  return readJson<SuppressionBody>("/api/suppression/rules");
}

export async function addSuppressionRule(rule: ProposedRule): Promise<SuppressionRule> {
  return readJson<SuppressionRule>("/api/suppression/rules", {
    method: "POST",
    body: JSON.stringify(rule),
  });
}

export async function removeSuppressionRule(id: string): Promise<void> {
  await request(`/api/suppression/rules/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function loadIncidents(): Promise<void> {
  const body = await readJson<IncidentRow[]>("/api/incidents");
  useApp.getState().setIncidents(body);
}

export interface TimelineEntry {
  at: string | null;
  kind: string;
  title: string;
  detail: string;
  severity: string | null;
  detector: string | null;
  attackType: string | null;
  sourceIp: string | null;
  targetIp: string | null;
  alertId: string | null;
  occurrences: number;
  simulated: boolean;
}

export interface IncidentDetail {
  id: string;
  sourceIp: string;
  openedAt: string | null;
  status: string;
  highestSeverity: string | null;
  alertCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  detectors: string[];
  attackTypes: string[];
  timeline: TimelineEntry[];
  alerts: FeedAlert[];
}

export async function loadIncidentDetail(id: string): Promise<IncidentDetail> {
  return readJson<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`);
}

export interface EventFilter {
  text?: string;
  severity?: string;
  attackType?: string;
  detector?: string;
  source?: string;
  target?: string;
  simulated?: boolean;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export interface EventSearchBody {
  total: number;
  offset: number;
  limit: number;
  events: FeedAlert[];
}

export function eventQuery(filter: EventFilter): string {
  const params = new URLSearchParams();
  if (filter.text?.trim()) params.set("q", filter.text.trim());
  if (filter.severity) params.set("severity", filter.severity);
  if (filter.attackType) params.set("attackType", filter.attackType);
  if (filter.detector?.trim()) params.set("detector", filter.detector.trim());
  if (filter.source?.trim()) params.set("source", filter.source.trim());
  if (filter.target?.trim()) params.set("target", filter.target.trim());
  if (filter.simulated !== undefined) params.set("simulated", String(filter.simulated));
  if (filter.from) params.set("from", filter.from);
  if (filter.to) params.set("to", filter.to);
  if (filter.limit !== undefined) params.set("limit", String(filter.limit));
  if (filter.offset !== undefined) params.set("offset", String(filter.offset));
  const query = params.toString();
  return query ? `?${query}` : "";
}

export async function searchEvents(filter: EventFilter): Promise<EventSearchBody> {
  return readJson<EventSearchBody>(`/api/events${eventQuery(filter)}`);
}

export async function loadFlows(limit = 500): Promise<FlowRow[]> {
  return readJson<FlowRow[]>(`/api/flows?limit=${limit}`);
}

export async function loadFlowHistory(limit = 500): Promise<FlowRow[]> {
  return readJson<FlowRow[]>(`/api/flows/history?limit=${limit}`);
}

export interface MlStatus {
  enabled: boolean;
  modelState: string;
  samples: number;
  clusters: number;
  threshold: number;
  lastTrainedAt: string;
  scored: number;
  anomalies: number;
  alerts: number;
  excluded: number;
  lastError: string;
}

export async function loadMlStatus(): Promise<MlStatus> {
  return readJson<MlStatus>("/api/ml/status");
}

export interface MetricsBody {
  uptimeSeconds: number;
  processedEvents: number;
  droppedEvents: number;
  queueDepth: number;
  detectedAlerts: number;
  deliveredAlerts: number;
  activeAlerts: number;
  streamClients: number;
  streamFrames: number;
  flowsActive: number;
  flowsClosed: number;
  storeEnabled: boolean;
  flowRows: number;
  alertRows: number;
  queuedRows: number;
  writtenRows: number;
  droppedRows: number;
  modelState: string;
  modelSamples: number;
  modelScored: number;
  anomalies: number;
  excludedFromTraining: number;
  importState: string;
  importReplayed: number;
  heapUsedBytes: number;
  heapMaxBytes: number;
  liveThreads: number;
}

export async function loadMetrics(): Promise<MetricsBody> {
  return readJson<MetricsBody>("/api/metrics");
}

export interface EvaluationPoint {
  threshold: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
  accuracy: number;
}

export interface EvaluationRule {
  alerted: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
  accuracy: number;
}

export interface EvaluationRun {
  id: string;
  source: string;
  startedAt: string;
  samples: number;
  attackSamples: number;
  benignSamples: number;
  rules: EvaluationRule;
  point: EvaluationPoint | null;
}

export interface EvaluationReport {
  available: boolean;
  reason: string;
  generatedAt: string;
  modelState: string;
  trainingSamples: number;
  samples: number;
  attackSamples: number;
  benignSamples: number;
  threshold: number;
  chosen: EvaluationPoint | null;
  best: EvaluationPoint | null;
  rules: EvaluationRule | null;
  sweep: EvaluationPoint[];
  runs: EvaluationRun[];
  note: string;
}

export interface MlDataset {
  samples: number;
  attackSamples: number;
  benignSamples: number;
  runs: number;
  runIds: string[];
  lastAddedAt: string;
}

export async function loadMlDataset(): Promise<MlDataset> {
  return readJson<MlDataset>("/api/ml/evaluation");
}

export async function evaluateModel(): Promise<EvaluationReport> {
  return readJson<EvaluationReport>("/api/ml/evaluate", { method: "POST" });
}

export interface CorrelationStatus {
  enabled: boolean;
  trackedSources: number;
  signals: number;
  correlated: number;
  minSignals: number;
  windowSeconds: number;
  chains?: number;
  chainsMatched?: number;
  lastChain?: string;
  chainProblem?: string;
}

export async function loadCorrelationStatus(): Promise<CorrelationStatus> {
  return readJson<CorrelationStatus>("/api/correlation/status");
}

export interface ContainmentAction {
  ip: string;
  blockedAt: string;
  expiresAt: string;
  reason: string;
  actor: string;
  automatic: boolean;
}

export interface ContainmentBody {
  enabled: boolean;
  auto: boolean;
  enforce: boolean;
  mode: "OFF" | "IDS" | "IPS";
  minSeverity: string;
  blocked: ContainmentAction[];
  droppedEvents: number;
  automaticActions: number;
  expiredActions: number;
  refusedActions: number;
  safeguards: {
    allowlist: string[];
    maxPerMinute: number;
    partitionCheck: boolean;
    refusedAllowlist: number;
    refusedRateLimit: number;
    refusedPartition: number;
  };
}

export async function loadContainment(): Promise<ContainmentBody> {
  return readJson<ContainmentBody>("/api/containment");
}

export async function containSource(ip: string, minutes: number, reason: string): Promise<void> {
  await request("/api/containment", {
    method: "POST",
    body: JSON.stringify({ ip, minutes, reason }),
  });
}

export async function releaseSource(ip: string): Promise<void> {
  await request("/api/containment/release", {
    method: "POST",
    body: JSON.stringify({ ip }),
  });
}

export async function setContainmentMode(
  mode: "OFF" | "IDS" | "IPS",
  password: string,
): Promise<{ mode: string; enabled: boolean; enforce: boolean }> {
  return readJson("/api/containment/mode", {
    method: "POST",
    body: JSON.stringify({ mode, password }),
  });
}

export interface NotificationRow {
  id: string;
  timestamp: string;
  severity: string;
  attackType: string;
  sourceIp: string;
  targetIp: string;
  summary: string;
  channel: string;
  escalation: boolean;
}

export interface DeliveryRow {
  at: string;
  channel: string;
  outcome: string;
  attempts: number;
  detail: string;
}

export interface NotificationHealth {
  console: boolean;
  email: boolean;
  emailRecipient: string;
  webhookHost: string;
  webhookRefusal: string;
  breakerOpen: boolean;
  consecutiveFailures: number;
  breakerUntil: string;
  suppressed: number;
  rateLimited: number;
  cooldownSkipped: number;
  refused: number;
  consoleSent: number;
  emailSent: number;
  emailFailed: number;
}

export interface NotificationSettings {
  retries: number;
  backoffMillis: number;
  breakerThreshold: number;
  breakerCooldownSeconds: number;
  maxPerHour: number;
  cooldownSeconds: number;
  maxBodyBytes: number;
  allowInsecure: boolean;
  redact: boolean;
}

export interface NotificationsBody {
  enabled: boolean;
  minimumSeverity: string;
  webhookConfigured: boolean;
  recorded: number;
  webhookSent: number;
  webhookFailed: number;
  dropped: number;
  lastError: string;
  notifications: NotificationRow[];
  health: NotificationHealth;
  settings: NotificationSettings;
  deliveries: DeliveryRow[];
}

export async function loadNotifications(limit = 20): Promise<NotificationsBody> {
  return readJson<NotificationsBody>(`/api/notifications?limit=${limit}`);
}

export async function testNotifications(): Promise<{ deliveries: DeliveryRow[] }> {
  return readJson("/api/notifications/test", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function setNotificationsEnabled(
  enabled: boolean,
  password: string,
): Promise<{ enabled: boolean }> {
  return readJson("/api/notifications/control", {
    method: "POST",
    body: JSON.stringify({ enabled, password }),
  });
}

export interface ComplianceBody {
  storeEnabled: boolean;
  databasePath: string;
  storedFlows: number;
  storedAlerts: number;
  droppedRows: number;
  retentionMinutes: number;
  sweepMinutes: number;
  retentionCutoff: string;
  auditCapacity: number;
  auditRecords: number;
  auditDenied: number;
  auditFailed: number;
  notificationsEnabled: boolean;
  notificationBacklog: number;
  containmentEnabled: boolean;
  containedSources: number;
  forensicsEnabled: boolean;
  evidenceDirectory: string;
  controls: ControlRow[];
  mappingNote: string;
}

export interface ControlRow {
  id: string;
  title: string;
  status: string;
  evidence: string;
  indicative: boolean;
}

export type ExportKind = "alerts" | "events" | "incidents" | "flows";

export function exportUrl(kind: ExportKind, format: "csv" | "json"): string {
  return `/api/export/${kind}?format=${format}`;
}

export async function setRetention(
  minutes: number,
  password: string,
  sweepNow: boolean,
): Promise<{ retentionMinutes: number; previousMinutes: number; sweptRows: number; storeEnabled: boolean }> {
  return readJson("/api/retention", {
    method: "POST",
    body: JSON.stringify({ minutes, password, sweepNow }),
  });
}

export async function loadCompliance(): Promise<ComplianceBody> {
  return readJson<ComplianceBody>("/api/compliance/summary");
}

export interface AuditRow {
  sequence: number;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  outcome: string;
  detail: string;
}

export interface AuditBody {
  entries: AuditRow[];
  denied: number;
  failed: number;
  capacity: number;
}

export async function loadAudit(limit = 20): Promise<AuditBody> {
  return readJson<AuditBody>(`/api/audit?limit=${limit}`);
}

export interface EvidenceBundle {
  directory: string;
  createdAt: string;
  files: number;
  bytes: number;
  manifestSha256: string;
}

export async function exportEvidence(): Promise<EvidenceBundle> {
  return readJson<EvidenceBundle>("/api/forensics/export", { method: "POST" });
}

export interface ImportLabelRow {
  label: string;
  flows: number;
  alerts: number;
}

export interface ImportReport {
  source: string;
  labelsSource: string | null;
  flows: number;
  skipped: number;
  events: number;
  unknownHosts: number;
  stored: number;
  detected: number;
  alerts: number;
  folded: number;
  paced: boolean;
  speed: number;
  elapsedMillis: number;
  completed: boolean;
  firstTimestamp: string | null;
  lastTimestamp: string | null;
  unknownHostIps: string[];
  problems: string[];
  labels: ImportLabelRow[];
}

export type ImportState = "IDLE" | "RUNNING" | "DONE" | "FAILED" | "CANCELLED";

export interface ImportStatus {
  state: ImportState;
  source: string | null;
  flows: number;
  replayed: number;
  progress: number;
  alerts: number;
  paced: boolean;
  speed: number;
  elapsedMillis: number;
  error: string | null;
  lastReport: ImportReport | null;
}

export interface ImportSample {
  connLog: string;
  labels: string;
  source: string;
  labelsName: string;
}

export interface ImportRequest {
  connLog: string;
  labels?: string;
  source: string;
  labelsName?: string;
  speed: number;
}

export async function loadImportStatus(): Promise<ImportStatus> {
  return readJson<ImportStatus>("/api/import/status");
}

export async function loadImportSample(): Promise<ImportSample> {
  return readJson<ImportSample>("/api/import/sample");
}

export async function startImport(body: ImportRequest): Promise<ImportStatus> {
  return readJson<ImportStatus>("/api/import/zeek", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function runPlan(input?: { excludedHostIds: string[]; teamCapacities: SocTeam[] }): Promise<PlanBody> {
  const body = await readJson<PlanBody>("/api/response/run", {
    method: "POST",
    body: input ? JSON.stringify(input) : undefined,
  });
  useApp.getState().setPlan(body);
  return body;
}

export interface IntelStatus {
  enabled: boolean;
  feed: string;
  wired: boolean;
  entries: number;
  addresses: number;
  domains: number;
  digests: number;
  skipped: number;
  expired: number;
  source: string;
  lastReloadAt: string | null;
}

export function loadIntelStatus(): Promise<IntelStatus> {
  return readJson<IntelStatus>("/api/intel/status");
}

export function reloadIntel(password: string): Promise<IntelStatus> {
  return readJson<IntelStatus>("/api/intel/reload", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export interface ScenarioResult {
  preset: string;
  title: string;
  source: string;
  target: string;
  events: number;
  attackTypes: string[];
}

export function runScenario(
  preset: string,
  source?: string,
  target?: string,
): Promise<ScenarioResult> {
  return readJson<ScenarioResult>("/api/scenarios", {
    method: "POST",
    body: JSON.stringify({ preset, source, target }),
  });
}
