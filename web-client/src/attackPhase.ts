export type AttackPhase = "idle" | "traveling" | "impact";

export interface AttackState {
  active: boolean;
  phase: AttackPhase;
  sourceId: string | null;
  targetId: string | null;
  token: number;
}

const EMPTY: AttackState = {
  active: false,
  phase: "idle",
  sourceId: null,
  targetId: null,
  token: 0,
};

const listeners = new Set<() => void>();
let current: AttackState = EMPTY;

function emit() {
  listeners.forEach((listener) => listener());
}

export function getAttackState(): AttackState {
  return current;
}

export function getAttackPhase(): AttackPhase {
  return current.phase;
}

export function subscribeAttackPhase(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function resetAttackState() {
  if (!current.active && current.phase === "idle" && current.sourceId === null && current.targetId === null) return;
  current = { active: false, phase: "idle", sourceId: null, targetId: null, token: current.token };
  emit();
}

export function setAttackPhase(next: AttackPhase) {
  if (current.phase === next) return;
  if (next === "idle") {
    current = { active: false, phase: "idle", sourceId: null, targetId: null, token: current.token };
  } else {
    current = { ...current, phase: next, active: true };
  }
  emit();
}

export function startAttack(sourceId: string, targetId: string) {
  if (current.phase !== "idle") return;
  if (!sourceId || !targetId || sourceId === targetId) return;
  current = {
    active: true,
    phase: "traveling",
    sourceId,
    targetId,
    token: Date.now(),
  };
  emit();
}
