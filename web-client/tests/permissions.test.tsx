import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, test } from "vitest";
import { NavList } from "../src/components/NavList";
import { navEntries } from "../src/permissions";

describe("role gating", () => {
  test("a viewer cannot see attack controls or admin", () => {
    const labels = navEntries("Viewer").map((entry) => entry.label);
    expect(labels).not.toContain("Attack lab");
    expect(labels).not.toContain("Control");
    expect(labels).not.toContain("Planner");
    expect(labels).not.toContain("Admin");
    expect(labels).toContain("Overview");
    render(
      <MemoryRouter>
        <NavList role="Viewer" />
      </MemoryRouter>,
    );
    expect(screen.queryByText("Attack lab")).toBeNull();
    expect(screen.queryByText("Admin")).toBeNull();
    expect(screen.getByText("Overview")).toBeTruthy();
  });
});
