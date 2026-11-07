import { sampleMotion } from "./motion";

export const PARTICLE_CAP = 8;
export const ATTACK_SLOTS = 4;
export const particleBudget = { current: PARTICLE_CAP };

export function attackSlots(budget: number): number {
  return Math.min(ATTACK_SLOTS, clampParticles(budget));
}
export const SLOW_FRAME_MS = 20;
export const LEAVE_MS = 200;
export const ENTER_MS = 300;
export const STAGGER_S = 0.04;

export type ScreenName = "landing" | "roles" | "login" | "overview" | "attack" | "alerts" | "portal";

export function screenForPath(path: string): ScreenName {
  if (path === "/" || path === "") return "landing";
  if (path.startsWith("/roles")) return "roles";
  if (path.startsWith("/login")) return "login";
  if (path === "/portal" || path === "/portal/") return "overview";
  if (path.startsWith("/portal/attack")) return "attack";
  if (path.startsWith("/portal/alerts")) return "alerts";
  return "portal";
}

export function contentShift(from: number, to: number, t: number, reduced: boolean): number {
  return sampleMotion(from, to, reduced ? 1 : t, reduced);
}

export function focusHold(elapsedMs: number, reduced: boolean): "focus" | "home" {
  if (reduced) return "home";
  return elapsedMs < 900 ? "focus" : "home";
}

export interface FitPose {
  x: number;
  y: number;
  z: number;
  lookX: number;
  lookY: number;
  lookZ: number;
}

export function fitPose(points: { x: number; z: number }[], fovDeg = 42): FitPose {
  if (points.length === 0) {
    return { x: 0, y: 8, z: 14, lookX: 0, lookY: 0, lookZ: 0 };
  }
  let minX = points[0].x;
  let maxX = points[0].x;
  let minZ = points[0].z;
  let maxZ = points[0].z;
  for (const point of points) {
    if (point.x < minX) minX = point.x;
    if (point.x > maxX) maxX = point.x;
    if (point.z < minZ) minZ = point.z;
    if (point.z > maxZ) maxZ = point.z;
  }
  const lookX = (minX + maxX) / 2;
  const lookZ = (minZ + maxZ) / 2;
  const radius = Math.max(Math.hypot(maxX - lookX, maxZ - lookZ), 1.5);
  const fov = (fovDeg * Math.PI) / 180;
  const distance = (radius / Math.sin(fov / 2)) * 0.92;
  return {
    x: lookX,
    y: distance * 0.72,
    z: lookZ + distance * 0.78,
    lookX,
    lookY: 0,
    lookZ,
  };
}

export function clampParticles(count: number): number {
  if (!Number.isFinite(count) || count <= 0) return 0;
  if (count > PARTICLE_CAP) return PARTICLE_CAP;
  return Math.floor(count);
}

export function nextParticleBudget(current: number, frameMs: number, reduced: boolean): number {
  if (reduced) return 0;
  const held = clampParticles(current);
  if (frameMs > SLOW_FRAME_MS) return Math.max(0, held - 1);
  if (held < PARTICLE_CAP) return held + 1;
  return PARTICLE_CAP;
}

export interface CameraPose extends FitPose {
  dim: number;
}

export function cameraPose(
  screen: ScreenName,
  fit: FitPose,
  focus: { x: number; y: number; z: number } | null,
): CameraPose {
  if (screen === "roles") {
    const span = fit.z - fit.lookZ;
    return {
      x: fit.lookX,
      y: fit.y * 0.78,
      z: fit.lookZ + span * 0.78,
      lookX: fit.lookX,
      lookY: 0,
      lookZ: fit.lookZ,
      dim: 0,
    };
  }
  if (screen === "login") {
    const span = fit.z - fit.lookZ;
    return {
      x: fit.lookX + 0.6,
      y: fit.y * 0.5,
      z: fit.lookZ + span * 0.48,
      lookX: fit.lookX,
      lookY: 0.1,
      lookZ: fit.lookZ,
      dim: 0,
    };
  }
  if (screen === "attack" && focus) {
    return {
      x: focus.x + 1.6,
      y: 3.2,
      z: focus.z + 4.2,
      lookX: focus.x,
      lookY: 0,
      lookZ: focus.z,
      dim: 0,
    };
  }
  if (screen === "alerts") {
    return { ...fit, dim: 0.55 };
  }
  return { ...fit, dim: 0 };
}

export const landingDolly = { z: 16 };
