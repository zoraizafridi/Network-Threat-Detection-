import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { Suspense } from "react";
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
      {/* AppRoutes renders lazy page components; App always mounts it inside a
          Suspense boundary (see RouteStage). Mounting it bare here made the
          first navigation to a lazy route suspend with no fallback, which is
          why the redirect assertion could never settle. */}
      <Suspense fallback={<p>loading</p>}>
        <AppRoutes />
      </Suspense>
      <PathProbe />
    </MemoryRouter>,
  );
}

describe("portal routing", () => {
  afterEach(cleanup);

  test("the legacy overview address redirects to the portal index", async () => {
    mount("/portal/overview");
    // The redirect lives in a lazily loaded route tree, so the lazy import plus the
    // Navigate effect has to settle. Give that a real budget: with the whole suite
    // running in parallel the import can take well over the 1s default.
    await waitFor(() => expect(screen.getByTestId("path").textContent).toBe("/portal"), { timeout: 5000 });
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
