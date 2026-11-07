import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Outlet, useLocation } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { AppRoutes } from "../src/App";

vi.mock("../src/pages/Shell", () => ({
  Shell: () => (
    <div>
      <span data-testid="shell" />
      <Outlet />
    </div>
  ),
}));

vi.mock("lenis", () => ({
  default: class {
    on() {}
    stop() {}
    raf() {}
    scrollTo() {}
    destroy() {}
  },
}));

function PathProbe() {
  const location = useLocation();
  return <span data-testid="path">{location.pathname}</span>;
}

function mount(path: string) {
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
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
      <PathProbe />
    </MemoryRouter>,
  );
}

describe("portal routing", () => {
  afterEach(cleanup);

  test("the legacy overview address redirects to the portal index", async () => {
    mount("/portal/overview");
    await waitFor(() => expect(screen.getByTestId("path").textContent).toBe("/portal"));
  });

  test("unknown portal addresses render the not found page", async () => {
    mount("/portal/nope");
    expect(await screen.findByRole("heading", { name: "Not found" })).toBeTruthy();
    expect(screen.getByTestId("path").textContent).toBe("/portal/nope");
  });

  test("the landing page renders outside the portal shell", async () => {
    mount("/");
    expect(screen.queryByTestId("shell")).toBeNull();
    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading.textContent ?? "").toMatch(/Detection/);
  });
});
