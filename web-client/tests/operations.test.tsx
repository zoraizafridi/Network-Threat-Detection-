import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { AdminPage } from "../src/pages/Admin";
import { useApp } from "../src/store";

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
      excluded: 0,
      lastError: "",
    },
    dataset: {
      samples: 120,
      attackSamples: 80,
      benignSamples: 40,
      runs: 2,
      runIds: ["run-1", "run-2"],
      lastAddedAt: "2026-11-08T08:00:00Z",
    },
    metrics: {
      uptimeSeconds: 3600,
      processedEvents: 12000,
      droppedEvents: 0,
      queueDepth: 2,
      detectedAlerts: 40,
      deliveredAlerts: 38,
      activeAlerts: 6,
      streamClients: 1,
      streamFrames: 900,
      flowsActive: 12,
      flowsClosed: 300,
      storeEnabled: true,
      flowRows: 40,
      alertRows: 3,
      queuedRows: 0,
      writtenRows: 43,
      droppedRows: 0,
      modelState: "TRAINED",
      modelSamples: 120,
      modelScored: 240,
      anomalies: 4,
      excludedFromTraining: 0,
      importState: "IDLE",
      importReplayed: 0,
      heapUsedBytes: 134217728,
      heapMaxBytes: 536870912,
      liveThreads: 18,
    },
    intel: {
      enabled: true,
      feed: "config/intel.json",
      wired: true,
      entries: 50,
      addresses: 20,
      domains: 15,
      digests: 15,
      skipped: 0,
      expired: 1,
      source: "config/intel.json",
      lastReloadAt: null,
    },
    correlation: {
      enabled: true,
      trackedSources: 3,
      signals: 9,
      correlated: 2,
      minSignals: 3,
      windowSeconds: 120,
      chains: 3,
      chainsMatched: 1,
      lastChain: "scan-to-exfil",
      chainProblem: "",
    },
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
      mode: "IPS",
      minSeverity: "HIGH",
      droppedEvents: 0,
      automaticActions: 0,
      expiredActions: 1,
      refusedActions: 0,
      safeguards: {
        allowlist: ["10.0.0.1"],
        maxPerMinute: 5,
        partitionCheck: true,
        refusedAllowlist: 0,
        refusedRateLimit: 0,
        refusedPartition: 0,
      },
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
          escalation: false,
        },
      ],
      health: {
        console: true,
        email: false,
        emailRecipient: "",
        webhookHost: "",
        webhookRefusal: "",
        breakerOpen: false,
        consecutiveFailures: 0,
        breakerUntil: "",
        suppressed: 0,
        rateLimited: 0,
        cooldownSkipped: 0,
        refused: 0,
        consoleSent: 2,
        emailSent: 0,
        emailFailed: 0,
      },
      settings: {
        retries: 2,
        backoffMillis: 250,
        breakerThreshold: 5,
        breakerCooldownSeconds: 60,
        maxPerHour: 60,
        cooldownSeconds: 30,
        maxBodyBytes: 4096,
        allowInsecure: false,
        redact: true,
      },
      deliveries: [],
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
      controls: [
        {
          id: "CC6.1",
          title: "Logical access",
          status: "MET",
          evidence: "audit trail keeps the actor and the outcome",
          indicative: true,
        },
      ],
      mappingNote: "The control mapping is indicative, not a certification.",
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
    suppression: {
      enabled: true,
      file: "config/suppression-rules.json",
      count: 1,
      rules: [
        {
          id: "sr-00000001",
          detector: "AnomalyDetector",
          attackType: "DATA_TRANSFER",
          sourceIp: "10.0.0.5",
          targetIp: "",
          maxSeverity: "LOW",
          note: "nightly backup",
          createdBy: "admin",
          createdAt: "2026-11-08T08:00:00Z",
          enabled: true,
          describe: "detector AnomalyDetector, type DATA_TRANSFER, source 10.0.0.5, any target, at or below LOW",
        },
      ],
    },
    blockStatus: 0,
    releaseStatus: 0,
    exportStatus: 0,
    suppressionStatus: 0,
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
    loadSuppressionRules: async () => state.suppression,
    loadMlDataset: async () => state.dataset,
    loadMetrics: async () => state.metrics,
    loadIntelStatus: async () => state.intel,
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
    addSuppressionRule: async (rule: { detector: string; attackType: string; sourceIp: string; targetIp: string; maxSeverity: string; note: string }) => {
      state.calls.push(
        `rule add ${rule.detector}|${rule.attackType}|${rule.sourceIp}|${rule.targetIp}|${rule.maxSeverity}|${rule.note}`,
      );
      if (state.suppressionStatus !== 0) {
        throw new actual.HttpStatusError(state.suppressionStatus);
      }
      return {
        ...rule,
        id: "sr-00000002",
        enabled: true,
        createdBy: "admin",
        createdAt: "2026-11-08T09:10:00Z",
        describe: "detector AnomalyDetector, any type, any source, any target, at or below LOW",
      };
    },
    removeSuppressionRule: async (id: string) => {
      state.calls.push(`rule remove ${id}`);
      if (state.suppressionStatus !== 0) {
        throw new actual.HttpStatusError(state.suppressionStatus);
      }
    },
    evaluateModel: async () => ({
      available: true,
      threshold: 0.9,
      chosen: { precision: 0.8, recall: 0.75, f1: 0.77, falsePositiveRate: 0.05, accuracy: 0.9 },
      best: { threshold: 0.85, precision: 0.82, recall: 0.78, f1: 0.80, falsePositiveRate: 0.04, accuracy: 0.91 },
      rules: { alerted: 12, precision: 0.6, recall: 0.5, f1: 0.54, falsePositiveRate: 0.1, accuracy: 0.8 },
      sweep: [],
      runs: [],
    }),
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
      await screen.findByText(
        "120 samples, 3 clusters, threshold 0.92, 240 scored, 4 anomalies, 2 alerts, 0 excluded from training",
      ),
    ).toBeTruthy();
    expect(screen.getByText("2 correlated from 9 signals, 3 signal minimum, 120s window")).toBeTruthy();
    expect(screen.getByText("IPS")).toBeTruthy();
    expect(screen.getByText("3 rules, 1 matched, last scan-to-exfil")).toBeTruthy();
    expect(screen.getByText("1 blocked, 0 events dropped, 0 refused by a safeguard")).toBeTruthy();
    expect(
      screen.getByText(/events processed, 2 queued, 0 dropped, 40 detected, 38 delivered/),
    ).toBeTruthy();
    expect(screen.getByText("2 recorded, 0 sent, 0 failed, 0 dropped")).toBeTruthy();
    expect(
      screen.getByText("120 labelled flows (80 attack, 40 benign) from 2 replay runs"),
    ).toBeTruthy();
    expect(screen.getByText("50 (20 addresses, 15 domains, 15 digests)")).toBeTruthy();
  });

  test("a capability that is switched off says so instead of hiding", async () => {
    world.state.containment = { ...world.state.containment, enabled: false, blocked: [] };
    render(<AdminPage />);

    expect(
      await screen.findByText(
        "Containment is off. Switch the mode to IDS or IPS on the Control page to record blocks.",
      ),
    ).toBeTruthy();
    expect(screen.getByText("No addresses are contained.")).toBeTruthy();
  });

  test("a blocked address is listed with its reason and the account behind it", async () => {
    render(<AdminPage />);

    const row = (await screen.findByText("repeat scanner")).closest("tr") as HTMLElement;
    expect(within(row).getByText("203.0.113.9")).toBeTruthy();
    expect(within(row).getByText("admin")).toBeTruthy();
    expect(within(row).getByRole("button", { name: "Release" })).toBeTruthy();
  });

  test("blocking an address sends the order and reports it", async () => {
    render(<AdminPage />);
    await screen.findByText(/1 blocked, 0 events dropped/);

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
    await screen.findByText(/1 blocked, 0 events dropped/);

    fireEvent.change(screen.getByLabelText("Address to contain"), { target: { value: "198.51.100.7" } });
    fireEvent.click(screen.getByRole("button", { name: "Block" }));

    expect(
      await screen.findByText(
        "The server refused the block. Containment may be off, or a safeguard refused it.",
      ),
    ).toBeTruthy();
  });

  test("releasing an address that is not blocked says so", async () => {
    world.state.releaseStatus = 404;
    render(<AdminPage />);
    await screen.findByText(/1 blocked, 0 events dropped/);

    fireEvent.click(screen.getByRole("button", { name: "Release" }));

    expect(await screen.findByText("203.0.113.9 is not blocked.")).toBeTruthy();
    expect(world.state.calls).toContain("release 203.0.113.9");
  });

  test("the audit trail shows the actor, the action and the outcome", async () => {
    render(<AdminPage />);

    expect(await screen.findByText("containment.block")).toBeTruthy();
    expect(screen.getByText("Allowed")).toBeTruthy();

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

  test("the model evaluation panel shows the in-sample notice after a run", async () => {
    render(<AdminPage />);

    fireEvent.click(await screen.findByRole("button", { name: "Run evaluation" }));

    expect(await screen.findByText("In-sample: these flows were also used for training.")).toBeTruthy();
  });
});
