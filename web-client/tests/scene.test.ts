import { describe, expect, test } from "vitest";
import { hopPath } from "../src/path";
import { attackSlots, clampParticles, fitPose, focusHold, nextParticleBudget, PARTICLE_CAP } from "../src/scene";

describe("scene", () => {
  test("the particle cap holds", () => {
    expect(clampParticles(100)).toBe(PARTICLE_CAP);
    expect(clampParticles(PARTICLE_CAP)).toBe(PARTICLE_CAP);
    expect(clampParticles(-2)).toBe(0);
    let budget = PARTICLE_CAP;
    budget = nextParticleBudget(budget, 21, false);
    expect(budget).toBe(PARTICLE_CAP - 1);
    budget = nextParticleBudget(budget, 8, false);
    expect(budget).toBeLessThanOrEqual(PARTICLE_CAP);
    expect(nextParticleBudget(PARTICLE_CAP, 4, true)).toBe(0);
  });

  test("fit pose looks at the centre of the nodes", () => {
    const pose = fitPose([
      { x: -4, z: 0 },
      { x: 4, z: 0 },
    ]);
    expect(pose.lookX).toBe(0);
    expect(pose.lookZ).toBe(0);
    expect(pose.z).toBeGreaterThan(0);
  });

  test("attack particles stay inside the cap", () => {
    expect(attackSlots(100)).toBeLessThanOrEqual(PARTICLE_CAP);
    expect(attackSlots(2)).toBe(2);
    expect(attackSlots(0)).toBe(0);
    expect(focusHold(0, true)).toBe("home");
    expect(focusHold(100, false)).toBe("focus");
    expect(focusHold(900, false)).toBe("home");
  });

  test("packets follow links from source to target", () => {
    const path = hopPath(
      [
        { source: "a", target: "b" },
        { source: "b", target: "c" },
        { source: "a", target: "c" },
      ],
      "a",
      "c",
    );
    expect(path[0]).toBe("a");
    expect(path[path.length - 1]).toBe("c");
    expect(path.length).toBeGreaterThan(1);
  });
});
