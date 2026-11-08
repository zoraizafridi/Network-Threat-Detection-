import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { AdminPage } from "../src/pages/Admin";
import { useApp } from "../src/store";

/**
 * Everything the operations panels read, behind one mutable world so each test
 * can shift a single field (a capability switched off, a 409 from a mutation)
 * without restating the whole payload.
 */
const world = vi.hoisted(() => {
  const defaults = () => ({
    config: {
      thresholds: { "detection.cooldownSeconds": "5", "flow.api.max": "500" },
      session: { timeoutSeconds: 28800, csrfEnabled: true, loginMaxAttempts: 5, loginWindowSeconds: 300 },
      accounts: [
        { username: "admin", role: "Admin" },
        { username: "viewer", role: "Viewer" },
      ],
    },
    ml: {
      enabled: true,
      modelState: "TRAINED",
      samples: 120,
      clusters: 3,
      threshold: 0.92,
      lastTrainedAt: "2026-11-08T09:00:00Z",
      scored: 240,
      anomalies: 4,
      alerts: 2,
      lastError: "",
    },
    correlation: { enabled: true, trackedSources: 3, signals: 9, correlated: 2, minSignals: 3, windowSeconds: 120 },
    containment: {
      enabled: true,
      auto: false,
      enforce: false,
      blocked: [
        {
          ip: "203.0.113.9",
          blockedAt: "2026-11-08T08:00:00Z",
          expiresAt: "2026-11-08T08:30:00Z",
          reason: "repeat scanner",
          actor: "admin",
          automatic: false,
        },
      ],
      droppedEvents: 0,
      automaticActions: 0,
      expiredActions: 1,
    },
    notifications: {
      enabled: true,
      minimumSeverity: "HIGH",
      webhookConfigured: false,
      recorded: 2,
      webhookSent: 0,
      webhookFailed: 0,
      dropped: 0,
      lastError: "",
      notifications: [
        {
          id: "n1",
          timestamp: "2026-11-08T08:59:00Z",
          severity: "CRITICAL",
          attackType: "PORT_SCAN",
          sourceIp: "10.0.0.5",
          targetIp: "10.0.0.9",
          summary: "Port scan from 10.0.0.5",
          channel: "log",
        },
      ],
    },
    compliance: {
      storeEnabled: true,
      databasePath: "data/ntd.db",
      storedFlows: 40,
      storedAlerts: 3,
      droppedRows: 0,
      retentionMinutes: 1440,
      sweepMinutes: 10,
      retentionCutoff: "2026-11-07T09:00:00Z",
      auditCapacity: 500,
      auditRecords: 12,
      auditDenied: 1,
      auditFailed: 0,
      notificationsEnabled: true,
      notificationBacklog: 0,
      containmentEnabled: true,
      containedSources: 1,
      forensicsEnabled: true,
      evidenceDirectory: "data/evidence",
    },
    audit: {
      entries: [
        {
          sequence: 2,
          timestamp: "2026-11-08T08:59:00Z",
          actor: "admin",
          action: "containment.block",
          target: "203.0.113.9",
          outcome: "ALLOWED",
          detail: "for 30 minutes",
        },
        {
          sequence: 1,
          timestamp: "2026-11-08T08:58:00Z",
          actor: "viewer",
          action: "auth.login",
          target: "/api/login",
          outcome: "DENIED",
          detail: "wrong password",
        },
      ],
      denied: 1,
      failed: 0,
      capacity: 500,
    },
    blockStatus: 0,
    releaseStatus: 0,
    exportStatus: 0,
  });

  const state = { ...defaults(), calls: [] as string[] };
  return {
    state,
    reset() {
      Object.assign(state, defaults());
      state.calls.length = 0;
    },
  };
});

vi.mock("../src/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api")>();
  const state = world.state;
  return {
    ...actual,
    readJson: async () => state.config,
    loadMlStatus: async () => state.ml,
    loadCorrelationStatus: async () => state.correlation,
    loadContainment: async () => state.containment,
    loadNotifications: async () => state.notifications,
    loadCompliance: async () => state.compliance,
    loadAudit: async () => state.audit,
    // The mutations are recorded before they can refuse, so a test can assert
    // both the request that was sent and the message the panel shows for it.
    containSource: async (ip: string, minutes: number, reason: string) => {
      state.calls.push(`block ${ip} ${minutes} ${reason}`);
      if (state.blockStatus !== 0) {
        throw new actual.HttpStatusError(state.blockStatus);
      }
    },
    releaseSource: async (ip: string) => {
      state.calls.push(`release ${ip}`);
      if (state.releaseStatus !== 0) {
        throw new actual.HttpStatusError(state.releaseStatus);
      }
    },
    exportEvidence: async () => {
      state.calls.push("export");
      if (state.exportStatus !== 0) {
        throw new actual.HttpStatusError(state.exportStatus);
      }
      return {
        directory: "data/evidence/run-1",
        createdAt: "2026-11-08T09:00:00Z",
        files: 4,
        bytes: 2048,
        manifestSha256: "0123456789abcdef0123456789abcdef",
      };
    },
  };
});

describe("admin operations", () => {
  beforeEach(() => {
    world.reset();
    useApp.setState({ user: { username: "admin", role: "Admin" } });
  });

  afterEach(cleanup);

  test("the operations table reports what each component owns", async () => {
    render(<AdminPage />);

    expect(
      await screen.findByText("120 samples, 3 clusters, threshold 0.92, 240 scored, 4 anomalies, 2 alerts"),
    ).toBeTruthy();
    expect(screen.getByText("2 correlated from 9 signals, 3 signal minimum, 120s window")).toBeTruthy();
    expect(screen.getByText("1 blocked, enforcement off, 0 events dropped")).toBeTruthy();
    expect(screen.getByText("2 recorded, 0 sent, 0 failed, 0 dropped")).toBeTruthy();
  });

  test("a capability that is switched off says so instead of hiding", async () => {
    world.state.containment = { ...world.state.containment, enabled: false, blocked: [] };
    render(<AdminPage />);

    expect(
      await screen.findByText("Containment is off. Set containment.enabled=true to record blocks."),
    ).toBeTruthy();
    expect(screen.getByText("No addresses are contained.")).toBeTruthy();
  });

  test("a blocked address is listed with its reason and the account behind it", async () => {
    render(<AdminPage />);

    // The address and the actor also appear in the audit trail, so the row is
    // the unit of assertion rather than the page.
    const row = (await screen.findByText("repeat scanner")).closest("tr") as HTMLElement;
    expect(within(row).getByText("203.0.113.9")).toBeTruthy();
    expect(within(row).getByText("admin")).toBeTruthy();
    expect(within(row).getByRole("button", { name: "Release" })).toBeTruthy();
  });

  test("blocking an address sends the order and reports it", async () => {
    render(<AdminPage />);
    await screen.findByText(/1 blocked, enforcement off/);

    fireEvent.change(screen.getByLabelText("Address to contain"), { target: { value: "198.51.100.7" } });
    fireEvent.change(screen.getByLabelText("Minutes"), { target: { value: "15" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "repeat scanner" } });
    fireEvent.click(screen.getByRole("button", { name: "Block" }));

    expect(await screen.findByText("Contained 198.51.100.7 for 15 minutes.")).toBeTruthy();
    expect(world.state.calls).toContain("block 198.51.100.7 15 repeat scanner");
  });

  test("a 409 on block names the flag that turns containment on", async () => {
    world.state.blockStatus = 409;
    render(<AdminPage />);
    await screen.findByText(/1 blocked, enforcement off/);

    fireEvent.change(screen.getByLabelText("Address to contain"), { target: { value: "198.51.100.7" } });
    fireEvent.click(screen.getByRole("button", { name: "Block" }));

    expect(
      await screen.findByText("Containment is off on this server. Set containment.enabled=true to use it."),
    ).toBeTruthy();
  });

  test("releasing an address that is not blocked says so", async () => {
    world.state.releaseStatus = 404;
    render(<AdminPage />);
    await screen.findByText(/1 blocked, enforcement off/);

    fireEvent.click(screen.getByRole("button", { name: "Release" }));

    expect(await screen.findByText("203.0.113.9 is not blocked.")).toBeTruthy();
    expect(world.state.calls).toContain("release 203.0.113.9");
  });

  test("the audit trail shows the actor, the action and the outcome", async () => {
    render(<AdminPage />);

    expect(await screen.findByText("containment.block")).toBeTruthy();
    expect(screen.getByText("Allowed")).toBeTruthy();

    // The badge renders the readable label rather than the stored enum name,
    // and the actor name is repeated in the accounts panel, so the row is the
    // unit of assertion.
    const row = (screen.getByText("auth.login")).closest("tr") as HTMLElement;
    expect(within(row).getByText("viewer")).toBeTruthy();
    expect(within(row).getByText("/api/login")).toBeTruthy();
    expect(within(row).getByText("Denied")).toBeTruthy();
  });

  test("the compliance panel reports retention and the audit counters", async () => {
    render(<AdminPage />);

    expect(await screen.findByText("data/ntd.db")).toBeTruthy();
    expect(screen.getByText("40 flows, 3 alerts")).toBeTruthy();
    expect(screen.getByText("1440 minutes, cutoff 2026-11-07T09:00:00Z")).toBeTruthy();
    expect(screen.getByText("12 of 500 entries, 1 denied, 0 failed")).toBeTruthy();
  });

  test("export is off the table while forensics is disabled", async () => {
    world.state.compliance = { ...world.state.compliance, forensicsEnabled: false };
    render(<AdminPage />);

    expect(await screen.findByRole("button", { name: "Export bundle" })).toBeDisabled();
  });

  test("an export reports the directory it wrote", async () => {
    render(<AdminPage />);

    fireEvent.click(await screen.findByRole("button", { name: "Export bundle" }));

    expect(await screen.findByText("Evidence bundle written to data/evidence/run-1.")).toBeTruthy();
    expect(screen.getByText(/Last bundle: 4 files, 2048 bytes, manifest 0123456789abcdef\./)).toBeTruthy();
    expect(world.state.calls).toContain("export");
  });

  test("a viewer is refused the page before any endpoint is called", async () => {
    useApp.setState({ user: { username: "viewer", role: "Viewer" } });
    render(<AdminPage />);

    expect(screen.getByText("Access denied for role Viewer")).toBeTruthy();
    expect(screen.queryByText("Operations status")).toBeNull();
    expect(world.state.calls).toHaveLength(0);
  });
});
