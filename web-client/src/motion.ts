export function sampleMotion(from: number, to: number, t: number, reduced: boolean): number {
  if (reduced) {
    return to;
  }
  const clamped = t < 0 ? 0 : t > 1 ? 1 : t;
  const eased = 1 - (1 - clamped) ** 3;
  return from + (to - from) * eased;
}

export function motionMs(ms: number, reduced: boolean): number {
  return reduced ? 0 : ms;
}
