import { create } from "zustand";
import type { FeedAlert } from "./alerts";
import { sessionAfterStatus, type SessionUser } from "./session";
import type { Asset, IncidentRow, NetLink, PlanBody, SocTeam } from "./types";

export type AuthState = "unknown" | "in" | "out";

interface AppState {
  auth: AuthState;
  user: SessionUser | null;
  running: boolean;
  autoMode: boolean;
  alertCount: number;
  incidentCount: number;
  assets: Asset[];
  links: NetLink[];
  alerts: FeedAlert[];
  incidents: IncidentRow[];
  selectedId: string | null;
  disconnected: boolean;
  notice: string;
  plan: PlanBody | null;
  teams: SocTeam[];
  plannerView: { excluded: string[]; unreachable: string[]; pairs: { source: string; target: string; id: string }[]; hover: string | null; show: boolean } | null;
  report: string;
  riskHistory: Record<string, number[]>;
  attackToken: number;
  attack: { src: string; dst: string } | null;
  cue: { id: string; sourceIp: string; targetIp: string; severity: string } | null;
  edgePulse: number;
  holdId: string | null;
  setUser: (user: SessionUser) => void;
  markSignedOut: () => void;
  applyHttpStatus: (status: number) => void;
  setSimulation: (running: boolean, autoMode: boolean, alertCount: number, incidentCount: number) => void;
  setNetwork: (assets: Asset[], links: NetLink[], teams?: SocTeam[]) => void;
  setPlannerView: (view: AppState["plannerView"]) => void;
  pushAlert: (alert: FeedAlert) => void;
  setAlerts: (alerts: FeedAlert[]) => void;
  setIncidents: (incidents: IncidentRow[]) => void;
  setSelectedId: (id: string | null) => void;
  setDisconnected: (disconnected: boolean) => void;
  setNotice: (notice: string) => void;
  setPlan: (plan: PlanBody | null) => void;
  setReport: (report: string) => void;
  setAttack: (src: string, dst: string) => void;
  setHoldId: (holdId: string | null) => void;
}

export const useApp = create<AppState>((set) => ({
  auth: "unknown",
  user: null,
  running: false,
  autoMode: false,
  alertCount: 0,
  incidentCount: 0,
  assets: [],
  links: [],
  alerts: [],
  incidents: [],
  selectedId: null,
  disconnected: false,
  notice: "",
  plan: null,
  teams: [],
  plannerView: null,
  report: "",
  riskHistory: {},
  attackToken: 0,
  attack: null,
  cue: null,
  edgePulse: 0,
  holdId: null,
  setUser: (user) => set({ auth: "in", user, notice: "" }),
  markSignedOut: () => set({ auth: "out", user: null }),
  applyHttpStatus: (status) =>
    set((state) => {
      const user = sessionAfterStatus(state.user, status);
      if (status === 401) {
        return { auth: "out", user: null };
      }
      return { user };
    }),
  setSimulation: (running, autoMode, alertCount, incidentCount) =>
    set({ running, autoMode, alertCount, incidentCount }),
  setNetwork: (assets, links, teams) =>
    set((state) => {
      const riskHistory = { ...state.riskHistory };
      for (const asset of assets) {
        const previous = riskHistory[asset.id] ?? [];
        const last = previous[previous.length - 1];
        if (last !== asset.riskScore) {
          riskHistory[asset.id] = [...previous, asset.riskScore].slice(-40);
        }
      }
      return { assets, links, riskHistory, teams: teams ?? state.teams };
    }),
  setPlannerView: (plannerView) => set({ plannerView }),
  pushAlert: (alert) =>
    set((state) => {
      const recent = state.alerts.slice(-12);
      const duplicate = recent.some((row) => row.attackType === alert.attackType && row.sourceIp === alert.sourceIp && row.targetIp === alert.targetIp);
      if (duplicate) return state;
      return {
      alerts: [...state.alerts, alert],
      cue: {
        id: alert.id,
        sourceIp: alert.sourceIp,
        targetIp: alert.targetIp,
        severity: alert.severity,
      },
      edgePulse: alert.severity === "CRITICAL" ? state.edgePulse + 1 : state.edgePulse,
      };
    }),
  setAlerts: (alerts) => set({ alerts }),
  setIncidents: (incidents) => set({ incidents }),
  setSelectedId: (selectedId) => set({ selectedId }),
  setDisconnected: (disconnected) => set({ disconnected }),
  setNotice: (notice) => set({ notice }),
  setPlan: (plan) => set({ plan }),
  setReport: (report) => set({ report }),
  setAttack: (src, dst) => set((state) => ({ attack: { src, dst }, attackToken: state.attackToken + 1 })),
  setHoldId: (holdId) => set({ holdId }),
}));
