import type { FeedAlert } from "./alerts";
import { useApp } from "./store";
import type { Asset, IncidentRow, NetLink, PlanBody, SocTeam } from "./types";

export class HttpStatusError extends Error {
  status: number;

  constructor(status: number) {
    super(String(status));
    this.status = status;
  }
}

export async function request(path: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
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

export async function runPlan(input?: { excludedHostIds: string[]; teamCapacities: SocTeam[] }): Promise<PlanBody> {
  const body = await readJson<PlanBody>("/api/response/run", {
    method: "POST",
    body: input ? JSON.stringify(input) : undefined,
  });
  useApp.getState().setPlan(body);
  return body;
}
