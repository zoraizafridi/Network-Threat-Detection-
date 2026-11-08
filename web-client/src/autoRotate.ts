export const AUTO_ROTATE_SPEED = 0.6;

export const AUTO_ROTATE_RESUME_MS = 3000;

export interface AutoRotateInput {
  enabled: boolean;
  reducedMotion: boolean;
  dragging: boolean;
  idleMs: number;
  hasSelection: boolean;
  attackActive: boolean;
}

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
