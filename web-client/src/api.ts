import type { FeedAlert } from "./alerts";
import { useApp } from "./store";
import type { Asset, FlowRow, IncidentRow, NetLink, PlanBody, SocTeam } from "./types";

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
  const body = await readJson<{ assets: Asset[]; links: NetLink[]; teams?: SocTeam[] }>("/api/network");
  useApp.getState().setNetwork(body.assets, body.links, body.teams ?? []);
}

export async function loadAlerts(): Promise<void> {
  const body = await readJson<FeedAlert[]>("/api/alerts?limit=500");
  useApp.getState().setAlerts(body);
}

export async function loadIncidents(): Promise<void> {
  const body = await readJson<IncidentRow[]>("/api/incidents");
  useApp.getState().setIncidents(body);
}

/** Connection records. They are polled rather than streamed, so no store write. */
export async function loadFlows(limit = 500): Promise<FlowRow[]> {
  return readJson<FlowRow[]>(`/api/flows?limit=${limit}`);
}

/**
 * Records that outlived the in-memory ring because they reached the durable
 * store. The server answers 503 when the store is off, so callers must treat
 * that status as "not configured" rather than "nothing recorded".
 */
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
  lastError: string;
}

export async function loadMlStatus(): Promise<MlStatus> {
  return readJson<MlStatus>("/api/ml/status");
}

export interface CorrelationStatus {
  enabled: boolean;
  trackedSources: number;
  signals: number;
  correlated: number;
  minSignals: number;
  windowSeconds: number;
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
  blocked: ContainmentAction[];
  droppedEvents: number;
  automaticActions: number;
  expiredActions: number;
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

export interface NotificationRow {
  id: string;
  timestamp: string;
  severity: string;
  attackType: string;
  sourceIp: string;
  targetIp: string;
  summary: string;
  channel: string;
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
}

export async function loadNotifications(limit = 20): Promise<NotificationsBody> {
  return readJson<NotificationsBody>(`/api/notifications?limit=${limit}`);
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

export async function runPlan(input?: { excludedHostIds: string[]; teamCapacities: SocTeam[] }): Promise<PlanBody> {
  const body = await readJson<PlanBody>("/api/response/run", {
    method: "POST",
    body: input ? JSON.stringify(input) : undefined,
  });
  useApp.getState().setPlan(body);
  return body;
}
