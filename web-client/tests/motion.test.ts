import { describe, expect, test } from "vitest";
import { motionMs, sampleMotion } from "../src/motion";
import { cameraPose, contentShift, fitPose } from "../src/scene";

describe("reduced motion", () => {
  test("applies final states immediately", () => {
    expect(sampleMotion(0, 10, 0, true)).toBe(10);
    expect(sampleMotion(2, 8, 0.2, true)).toBe(8);
    expect(motionMs(600, true)).toBe(0);
    expect(sampleMotion(0, 10, 0, false)).toBe(0);
    expect(sampleMotion(0, 10, 1, false)).toBe(10);
    expect(motionMs(350, false)).toBe(350);
    expect(contentShift(12, 0, 0, true)).toBe(0);
    expect(contentShift(12, 0, 0.2, true)).toBe(0);
  });

  test("login sits closer than the wide overview pose", () => {
    const fit = fitPose([
      { x: -6, z: -2 },
      { x: 6, z: 4 },
    ]);
    const wide = cameraPose("overview", fit, null);
    const login = cameraPose("login", fit, null);
    const span = (pose: { x: number; z: number; lookX: number; lookZ: number }) =>
      Math.hypot(pose.x - pose.lookX, pose.z - pose.lookZ);
    expect(span(login)).toBeLessThan(span(wide));
    expect(cameraPose("alerts", fit, null).dim).toBeGreaterThan(0);
  });
});
