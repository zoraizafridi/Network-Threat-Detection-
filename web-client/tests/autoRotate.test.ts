import { describe, expect, test } from "vitest";
import {
  AUTO_ROTATE_RESUME_MS,
  AUTO_ROTATE_SPEED,
  shouldAutoRotate,
  type AutoRotateInput,
} from "../src/autoRotate";

const still: AutoRotateInput = {
  enabled: true,
  reducedMotion: false,
  dragging: false,
  idleMs: AUTO_ROTATE_RESUME_MS,
  hasSelection: false,
  attackActive: false,
};

describe("shouldAutoRotate", () => {
  test("turns by default once the map is idle", () => {
    expect(shouldAutoRotate(still)).toBe(true);
  });

  test("stops while the user drags", () => {
    expect(shouldAutoRotate({ ...still, dragging: true, idleMs: 60000 })).toBe(false);
  });

  test("waits the full resumption window after a drag", () => {
    expect(shouldAutoRotate({ ...still, idleMs: AUTO_ROTATE_RESUME_MS - 1 })).toBe(false);
    expect(shouldAutoRotate({ ...still, idleMs: AUTO_ROTATE_RESUME_MS })).toBe(true);
    expect(shouldAutoRotate({ ...still, idleMs: 0 })).toBe(false);
  });

  test("stops when the toggle is off", () => {
    expect(shouldAutoRotate({ ...still, enabled: false })).toBe(false);
  });

  test("never turns when the device asks for reduced motion", () => {
    expect(shouldAutoRotate({ ...still, reducedMotion: true })).toBe(false);
    expect(shouldAutoRotate({ ...still, reducedMotion: true, idleMs: 60000 })).toBe(false);
  });

  test("holds still while a host is hovered or selected", () => {
    expect(shouldAutoRotate({ ...still, hasSelection: true })).toBe(false);
    expect(shouldAutoRotate({ ...still, hasSelection: true, idleMs: 60000 })).toBe(false);
  });

  test("holds still while an attack highlight is on screen", () => {
    expect(shouldAutoRotate({ ...still, attackActive: true })).toBe(false);
  });

  test("each blocker wins on its own", () => {
    expect(
      shouldAutoRotate({
        enabled: true,
        reducedMotion: false,
        dragging: false,
        idleMs: 60000,
        hasSelection: false,
        attackActive: true,
      }),
    ).toBe(false);
  });

  test("takes one turn per hundred seconds", () => {
    expect(AUTO_ROTATE_SPEED).toBe(0.6);
    expect(AUTO_ROTATE_RESUME_MS).toBe(3000);
  });
});
