import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { FlowsPage } from "../src/pages/Flows";

/**
 * The live feed, the durable store and the status the store can refuse with.
 * They live in `vi.hoisted` because the factory below is hoisted above the
 * imports and would otherwise read them before they are assigned.
 */
const fixtures = vi.hoisted(() => {
  const live = [
    {
      id: "f1",
      srcIp: "10.0.0.5",
      dstIp: "10.0.0.9",
      srcPort: 41000,
      dstPort: 443,
      protocol: "TCP",
      bytesOut: 2048,
      bytesIn: 0,
      packets: 7,
      startTime: "2026-11-05T12:00:00Z",
      endTime: "2026-11-05T12:00:05Z",
      durationMs: 5000,
      flags: ["OK"],
      label: "NORMAL",
      simulated: false,
      ended: true,
    },
    {
      id: "f2",
      srcIp: "10.0.0.7",
      dstIp: "10.0.0.9",
      srcPort: 41002,
      dstPort: 8080,
      protocol: "UDP",
      bytesOut: 300,
      bytesIn: 0,
      packets: 2,
      startTime: "2026-11-05T12:01:00Z",
      endTime: "2026-11-05T12:01:01Z",
      durationMs: 1000,
      flags: ["FAILED"],
      label: "PORT_SCAN",
      simulated: false,
      ended: false,
    },
  ];
  return { live, stored: [] as typeof live, storedStatus: 0 };
});

vi.mock("../src/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api")>();
  return {
    ...actual,
    loadFlows: async () => fixtures.live,
    // The real history call refuses with a status error, so the page can tell a
    // store that is switched off from a store that is merely empty.
    loadFlowHistory: async () => {
      if (fixtures.storedStatus !== 0) {
        throw new actual.HttpStatusError(fixtures.storedStatus);
      }
      return fixtures.stored;
    },
  };
});

describe("flows page", () => {
  afterEach(() => {
    cleanup();
    fixtures.stored = [];
    fixtures.storedStatus = 0;
  });

  test("renders the records the API returned", async () => {
    render(<FlowsPage />);

    expect(await screen.findByText("10.0.0.5")).toBeTruthy();
    expect(screen.getByText("10.0.0.7")).toBeTruthy();
    expect(screen.getByText("2.0 KB")).toBeTruthy();
    // The label tally panel repeats each label, so the badge text is not unique.
    expect(screen.getAllByText("Port scan").length).toBeGreaterThan(0);
    expect(screen.getByText("Closed")).toBeTruthy();
    expect(screen.getByText("Open / failed")).toBeTruthy();
  });

  test("the search box narrows the table", async () => {
    render(<FlowsPage />);
    await screen.findByText("10.0.0.5");

    fireEvent.change(screen.getByLabelText("Search flows"), { target: { value: "8080" } });

    await waitFor(() => expect(screen.queryByText("10.0.0.5")).toBeNull());
    expect(screen.getByText("10.0.0.7")).toBeTruthy();
  });

  test("a search with no matches shows the empty state", async () => {
    render(<FlowsPage />);
    await screen.findByText("10.0.0.5");

    fireEvent.change(screen.getByLabelText("Search flows"), { target: { value: "203.0.113.99" } });

    expect(await screen.findByText("No flows match these filters.")).toBeTruthy();
    expect(screen.queryByText("10.0.0.5")).toBeNull();
  });

  test("pausing the feed keeps the rows on screen", async () => {
    render(<FlowsPage />);
    await screen.findByText("10.0.0.5");

    fireEvent.click(screen.getByRole("button", { name: "Pause" }));

    expect(screen.getByText("10.0.0.5")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Resume" })).toBeTruthy();
  });

  test("the Stored switch reads the durable store instead of the feed", async () => {
    fixtures.stored = [
      {
        id: "s1",
        srcIp: "192.0.2.50",
        dstIp: "10.0.0.9",
        srcPort: 50000,
        dstPort: 22,
        protocol: "TCP",
        bytesOut: 900,
        bytesIn: 0,
        packets: 3,
        startTime: "2026-11-05T10:00:00Z",
        endTime: "2026-11-05T10:00:02Z",
        durationMs: 2000,
        flags: ["OK"],
        label: "NORMAL",
        simulated: false,
        ended: true,
      },
    ];
    render(<FlowsPage />);
    await screen.findByText("10.0.0.5");

    fireEvent.click(screen.getByRole("button", { name: "Stored" }));

    expect(await screen.findByText("192.0.2.50")).toBeTruthy();
    expect(screen.queryByText("10.0.0.5")).toBeNull();
    expect(screen.getByText("Read from the durable store")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Stored" })).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(screen.getByRole("button", { name: "Live" }));

    expect(await screen.findByText("10.0.0.5")).toBeTruthy();
    expect(screen.getByText("Polling every 3 seconds")).toBeTruthy();
  });

  test("an empty store says so rather than looking broken", async () => {
    render(<FlowsPage />);
    await screen.findByText("10.0.0.5");

    fireEvent.click(screen.getByRole("button", { name: "Stored" }));

    expect(await screen.findByText(/No stored flows yet/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });

  test("a refused history call explains that the store is off", async () => {
    fixtures.storedStatus = 503;
    render(<FlowsPage />);
    await screen.findByText("10.0.0.5");

    fireEvent.click(screen.getByRole("button", { name: "Stored" }));

    expect(await screen.findByText(/The durable store is off/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
  });
});
