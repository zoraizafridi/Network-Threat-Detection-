import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, test, vi } from "vitest";
import { AppTree } from "../src/App";

vi.mock("../src/components/NetworkMap", () => ({
  NetworkMap: () => <div data-testid="scene-canvas" />,
  poseFromAssets: () => ({ x: 0, y: 8, z: 14, lookX: 0, lookY: 0, lookZ: 0 }),
}));

vi.mock("../src/api", () => ({
  loadState: () => Promise.resolve(),
  loadNetwork: () => Promise.resolve(),
  loadIncidents: () => Promise.resolve(),
  loadAlerts: () => Promise.resolve(),
  request: () => Promise.resolve(),
  readJson: () => Promise.resolve({}),
  applyState: () => undefined,
  runPlan: () => Promise.resolve(),
}));

vi.mock("../src/components/HeroNetwork", () => ({
  HeroNetwork: () => <div data-testid="hero-network" />,
}));

vi.mock("lenis", () => ({
  default: class {
    on() {}
    destroy() {}
    raf() {}
  },
}));

describe("persistent scene", () => {
  test("routes keep the scene mounted", () => {
    window.matchMedia = (query: string) =>
      ({
        matches: query.includes("reduce"),
        media: query,
        onchange: null,
        addListener: () => undefined,
        removeListener: () => undefined,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        dispatchEvent: () => false,
      }) as MediaQueryList;
    render(
      <MemoryRouter initialEntries={["/"]}>
        <AppTree />
      </MemoryRouter>,
    );
    const scene = screen.getByTestId("scene-root");
    fireEvent.click(screen.getAllByRole("button", { name: "Enter Portal" })[0]);
    expect(screen.getByTestId("scene-root")).toBe(scene);
    expect(screen.getByRole("heading", { name: "Welcome back." })).toBeTruthy();
  });
});
