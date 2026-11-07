/**
 * OrbitControls speed for the 3D map. Three.js treats 2.0 as one orbit every 30 seconds,
 * so 0.6 is one slow turn per 100 seconds.
 */
export const AUTO_ROTATE_SPEED = 0.6;

/** Quiet time after the last drag before the camera starts turning again. */
export const AUTO_ROTATE_RESUME_MS = 3000;

export interface AutoRotateInput {
  enabled: boolean;
  reducedMotion: boolean;
  dragging: boolean;
  idleMs: number;
  hasSelection: boolean;
  attackActive: boolean;
}

/**
 * The single place that decides whether the 3D camera may turn.
 *
 * The caller owns every input: the toggle, the media query, the OrbitControls drag state,
 * the time since the last drag, the focused or selected host and the attack highlight.
 * A hovered host is reported through hasSelection so the camera holds still while the
 * pointer rests on a node.
 */
export function shouldAutoRotate({
  enabled,
  reducedMotion,
  dragging,
  idleMs,
  hasSelection,
  attackActive,
}: AutoRotateInput): boolean {
  if (!enabled || reducedMotion) return false;
  if (dragging || idleMs < AUTO_ROTATE_RESUME_MS) return false;
  return !hasSelection && !attackActive;
}
