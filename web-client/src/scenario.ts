import { attackRoute } from "./mapPath";
import { request } from "./api";
import { useApp } from "./store";
import type { Asset } from "./types";

export const STAGE_NAMES = ["Recon", "Access", "Lateral movement", "Exfiltration"] as const;
const STAGE_TYPES = ["PORT_SCAN", "BRUTE_FORCE", "DOS_FLOOD", "DATA_TRANSFER"] as const;
const STAGE_MS = 4000;
const HOLD_MS = 3000;

export interface ScenarioSnap {
  phase: "idle" | "run" | "hold" | "paused";
  loop: boolean;
  stage: number;
  hop: number;
  speed: 1 | 2 | 4;
  attackerId: string | null;
  targetId: string | null;
  path: string[];
  marks: Record<string, "SUSPICIOUS" | "COMPROMISED">;
  frameKey: number;
  token: number;
  segmentFrom: string | null;
  segmentTo: string | null;
  segmentMs: number;
  lead: string;
}

const EMPTY: ScenarioSnap = {
  phase: "idle",
  loop: false,
  stage: -1,
  hop: 0,
  speed: 1,
  attackerId: null,
  targetId: null,
  path: [],
  marks: {},
  frameKey: 0,
  token: 0,
  segmentFrom: null,
  segmentTo: null,
  segmentMs: STAGE_MS,
  lead: STAGE_TYPES[0],
};

const listeners = new Set<() => void>();
let current: ScenarioSnap = EMPTY;
let timer: number | null = null;
let nextFn: () => void = () => undefined;
let sliceEnd = 0;
let pausedFrom: "run" | "hold" = "run";
let lastPair: { from: string; to: string; path: string[] } | null = null;
let pairCursor = 0;
let kindCursor = 0;
const posted = new Set<string>();

function emit() {
  listeners.forEach((listener) => listener());
}

export function getScenario(): ScenarioSnap {
  return current;
}

export function subscribeScenario(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function clearTimer() {
  if (timer !== null) window.clearTimeout(timer);
  timer = null;
}

function arm(ms: number, fn: () => void) {
  clearTimer();
  nextFn = fn;
  sliceEnd = performance.now() + ms;
  timer = window.setTimeout(fn, ms);
}

function stageMs(): number {
  return STAGE_MS / current.speed;
}

function candidates(assets: Asset[]): { from: string; to: string; path: string[] }[] {
  const rows: { from: string; to: string; path: string[] }[] = [];
  for (const from of assets) {
    for (const to of assets) {
      if (from.id === to.id) continue;
      const path = attackRoute(assets, from.id, to.id);
      if (path.length >= 3 && path[0] === from.id && path[path.length - 1] === to.id) {
        rows.push({ from: from.id, to: to.id, path });
      }
    }
  }
  return rows;
}

function pickPair(assets: Asset[], reuse: boolean): { from: string; to: string; path: string[] } | null {
  if (reuse && lastPair) return lastPair;
  const rows = candidates(assets);
  if (rows.length === 0) {
    if (assets.length < 2) return null;
    return { from: assets[0].id, to: assets[1].id, path: [assets[0].id, assets[1].id] };
  }
  const preferred = ["WORKSTATION", "SERVER", "IOT_DEVICE", "ROUTER"][kindCursor % 4];
  for (let offset = 0; offset < rows.length; offset += 1) {
    const row = rows[(pairCursor + offset) % rows.length];
    if (lastPair && row.from === lastPair.from && row.to === lastPair.to) continue;
    const target = assets.find((asset) => asset.id === row.to);
    if (preferred && target && target.type !== preferred) continue;
    pairCursor = (pairCursor + offset + 1) % rows.length;
    kindCursor += 1;
    return row;
  }
  const row = rows[pairCursor % rows.length];
  pairCursor = (pairCursor + 1) % rows.length;
  kindCursor += 1;
  return row;
}

function publish(alertType: string, stage: number, sourceId: string, targetId: string) {
  const assets = useApp.getState().assets;
  const source = assets.find((asset) => asset.id === sourceId);
  const target = assets.find((asset) => asset.id === targetId);
  if (!source || !target) return;
  const key = `${current.token}|${alertType}|${source.ip}|${target.ip}`;
  if (posted.has(key)) return;
  posted.add(key);
  useApp.getState().pushAlert({
    id: `sim-${current.token}-${stage}`,
    timestamp: new Date().toISOString(),
    severity: stage === 2 ? "CRITICAL" : stage === 0 ? "MEDIUM" : "HIGH",
    attackType: alertType,
    sourceIp: source.ip,
    targetIp: target.ip,
    detectorName: "Field station",
    description: STAGE_NAMES[stage] ?? alertType,
  });
  void request("/api/attacks", {
    method: "POST",
    body: JSON.stringify({ type: alertType, src: source.id, dst: target.id }),
  }).catch(() => undefined);
}

function lateralEdges(path: string[]): Array<[string, string]> {
  if (path.length <= 2) return [[path[0], path[1] ?? path[0]]];
  const edges: Array<[string, string]> = [];
  for (let index = 1; index < path.length - 1; index += 1) edges.push([path[index], path[index + 1]]);
  return edges;
}

function enterStage(stage: number) {
  const path = current.path;
  if (path.length < 2) return;
  const marks = { ...current.marks };
  let segmentFrom = path[0];
  let segmentTo = path[1];
  let hop = 0;
  let segment = stageMs();
  if (stage === 0) marks[path[1]] = "SUSPICIOUS";
  if (stage === 1) marks[path[1]] = "COMPROMISED";
  if (stage === 2) {
    const edges = lateralEdges(path);
    segmentFrom = edges[0][0];
    segmentTo = edges[0][1];
    segment = stageMs() / edges.length;
    marks[segmentTo] = "COMPROMISED";
  }
  if (stage === 3) {
    marks[path[path.length - 1]] = "COMPROMISED";
    segmentFrom = path[path.length - 1];
    segmentTo = path[0];
  }
  current = {
    ...current,
    phase: "run",
    stage,
    hop,
    marks,
    frameKey: current.frameKey + 1,
    segmentFrom,
    segmentTo,
    segmentMs: segment,
  };
  emit();
  publish(STAGE_TYPES[stage], stage, path[0], stage < 2 ? path[1] : path[path.length - 1]);
  if (stage === 2) arm(segment, onHop);
  else arm(segment, onStageDone);
}

function onHop() {
  const edges = lateralEdges(current.path);
  const next = current.hop + 1;
  if (next >= edges.length) {
    onStageDone();
    return;
  }
  const [from, to] = edges[next];
  current = {
    ...current,
    phase: "run",
    hop: next,
    marks: { ...current.marks, [to]: "COMPROMISED" },
    segmentFrom: from,
    segmentTo: to,
    segmentMs: stageMs() / edges.length,
  };
  emit();
  arm(current.segmentMs, onHop);
}

function onStageDone() {
  if (current.stage < 3) enterStage(current.stage + 1);
  else enterHold();
}

function enterHold() {
  current = {
    ...current,
    phase: "hold",
    stage: 4,
    segmentFrom: null,
    segmentTo: null,
    frameKey: current.frameKey + 1,
  };
  emit();
  arm(HOLD_MS / current.speed, () => {
    current = { ...current, marks: {} };
    emit();
    if (current.loop) begin(false);
    else {
      current = { ...current, phase: "idle", stage: -1 };
      emit();
    }
  });
}

function begin(reuse: boolean) {
  const assets = useApp.getState().assets;
  const pair = pickPair(assets, reuse);
  if (!pair) return;
  lastPair = pair;
  clearTimer();
  current = {
    ...current,
    phase: "run",
    stage: -1,
    hop: 0,
    attackerId: pair.from,
    targetId: pair.to,
    path: pair.path,
    marks: {},
    token: Date.now(),
    lead: STAGE_TYPES[kindCursor % 4],
    segmentFrom: null,
    segmentTo: null,
  };
  emit();
  enterStage(0);
}

export function scenarioStart(loop: boolean) {
  current = { ...current, loop };
  if (current.phase === "paused") {
    scenarioResume();
    return;
  }
  if (current.phase === "run" || current.phase === "hold") {
    emit();
    return;
  }
  begin(false);
}

export function scenarioSetLoop(loop: boolean) {
  current = { ...current, loop };
  if (loop && current.phase === "idle") begin(false);
  else emit();
}

export function scenarioHalt() {
  if (current.phase === "idle") return;
  clearTimer();
  pausedFrom = current.phase === "hold" ? "hold" : "run";
  current = { ...current, phase: "paused", loop: false };
  emit();
}

export function scenarioResume() {
  if (current.phase !== "paused") return;
  const left = Math.max(40, sliceEnd - performance.now());
  current = { ...current, phase: pausedFrom };
  emit();
  arm(left, nextFn);
}

export function scenarioPause() {
  if (current.phase !== "run" && current.phase !== "hold") return;
  pausedFrom = current.phase;
  clearTimer();
  current = { ...current, phase: "paused" };
  emit();
}

export function scenarioStep() {
  if (current.phase === "idle") return;
  const fn = nextFn;
  clearTimer();
  if (current.phase === "paused") current = { ...current, phase: pausedFrom };
  fn();
}

export function scenarioReplay() {
  if (!lastPair) return;
  clearTimer();
  current = { ...current, marks: {}, stage: -1 };
  begin(true);
}

export function scenarioReset() {
  clearTimer();
  posted.clear();
  lastPair = null;
  current = { ...EMPTY, speed: current.speed, frameKey: current.frameKey + 1 };
  emit();
}

export function scenarioSpeed(speed: 1 | 2 | 4) {
  if (current.speed === speed) return;
  const factor = current.speed / speed;
  current = { ...current, speed };
  if (timer !== null && (current.phase === "run" || current.phase === "hold")) {
    const left = Math.max(40, (sliceEnd - performance.now()) * factor);
    arm(left, nextFn);
  }
  emit();
}

export function scenarioLive(): boolean {
  return current.phase === "run" || current.phase === "paused";
}
