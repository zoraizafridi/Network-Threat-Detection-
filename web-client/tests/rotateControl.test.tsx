import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";
import { NetworkStage } from "../src/components/NetworkMap";
import type { Asset } from "../src/types";

const assets: Asset[] = [
  { id: "a", name: "Host A", ip: "10.0.0.1", type: "SERVER", criticality: 1, riskScore: 0, status: "NORMAL" },
  { id: "b", name: "Host B", ip: "10.0.0.2", type: "ROUTER", criticality: 2, riskScore: 0, status: "NORMAL" },
];

function reduceMotion(reduced: boolean) {
  window.matchMedia = ((query: string) => ({
    matches: reduced,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

function renderStage() {
  return render(<NetworkStage assets={assets} selectedId={null} onSelect={() => undefined} />);
}

beforeAll(() => {
  // The stage probes for WebGL once and caches the answer, so answer yes and start in 3D.
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockImplementation(
    () => ({ getExtension: () => ({ loseContext: () => undefined }) }) as unknown as RenderingContext,
  );
});

afterEach(() => {
  cleanup();
});

describe("rotate control", () => {
  test("sits next to the 3D and 2D buttons and starts pressed", () => {
    reduceMotion(false);
    renderStage();
    const labels = screen.getAllByRole("button").map((button) => button.textContent);
    expect(labels).toContain("3D");
    expect(labels).toContain("2D");
    const rotate = screen.getByRole("button", { name: "Rotate" });
    expect(rotate).toHaveAttribute("aria-pressed", "true");
    expect(rotate).not.toBeDisabled();
    expect(rotate.getAttribute("title")).toMatch(/one turn per 100 seconds/i);
    fireEvent.click(rotate);
    expect(rotate).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(rotate);
    expect(rotate).toHaveAttribute("aria-pressed", "true");
  });

  test("is hidden in the flat map", () => {
    reduceMotion(false);
    renderStage();
    fireEvent.click(screen.getByRole("button", { name: "2D" }));
    expect(screen.queryByRole("button", { name: "Rotate" })).toBeNull();
  });

  test("is off and disabled when the device asks for reduced motion", () => {
    reduceMotion(true);
    renderStage();
    const rotate = screen.getByRole("button", { name: "Rotate" });
    expect(rotate).toHaveAttribute("aria-pressed", "false");
    expect(rotate).toBeDisabled();
    expect(rotate.getAttribute("title")).toMatch(/reduced motion/i);
  });
});
