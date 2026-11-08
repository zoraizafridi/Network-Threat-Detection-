import { useCallback, useEffect, useState, type FormEvent } from "react";
import { EmptyState, Page, Panel, StatusBadge } from "../components/ui";
import {
  HttpStatusError,
  addSuppressionRule,
  containSource,
  evaluateModel,
  exportEvidence,
  loadAudit,
  loadCompliance,
  loadContainment,
  loadCorrelationStatus,
  loadIntelStatus,
  loadMetrics,
  loadMlDataset,
  loadMlStatus,
  loadNotifications,
  loadSuppressionRules,
  readJson,
  releaseSource,
  reloadIntel,
  removeSuppressionRule,
  setNotificationsEnabled,
  setRetention,
  testNotifications,
  type AuditBody,
  type ComplianceBody,
  type ContainmentBody,
  type CorrelationStatus,
  type EvidenceBundle,
  type EvaluationReport,
  type IntelStatus,
  type MetricsBody,
  type MlDataset,
  type MlStatus,
  type NotificationsBody,
  type ProposedRule,
  type SuppressionBody,
} from "../api";
import { clockTime, relativeTime } from "../format";
import { accessDenied, canSeeAdmin } from "../permissions";
import { useApp } from "../store";

const EMPTY_RULE: ProposedRule = {
  detector: "",
  attackType: "",
  sourceIp: "",
  targetIp: "",
  maxSeverity: "",
  note: "",
};

function ratio(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function megabytes(bytes: number): string {
  return `${Math.round(bytes / (1024 * 1024))} MB`;
}

function uptime(seconds: number): string {
  if (seconds < 90) return `${seconds}s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

function scoreCells(point: {
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
  accuracy: number;
} | null) {
  return (
    <>
      <td>{point ? ratio(point.precision) : "n/a"}</td>
      <td>{point ? ratio(point.recall) : "n/a"}</td>
      <td>{point ? ratio(point.f1) : "n/a"}</td>
      <td>{point ? ratio(point.falsePositiveRate) : "n/a"}</td>
      <td>{point ? ratio(point.accuracy) : "n/a"}</td>
    </>
  );
}

interface AdminConfig {
  thresholds: Record<string, string>;
  simulation?: {
    noiseEnabled: boolean;
    attackVariantChance: number;
    benignSpikeChance: number;
    retryChance: number;
    portSpreadChance: number;
  };
  session: {
    timeoutSeconds: number;
    absoluteTimeoutSeconds?: number;
    csrfEnabled: boolean;
    reauthEnabled?: boolean;
    reauthFreshSeconds?: number;
    loginMaxAttempts: number;
    loginWindowSeconds: number;
  };
  accounts: { username: string; role: string }[];
}

export function AdminPage() {
  const role = useApp((state) => state.user?.role ?? "");
  const [config, setConfig] = useState<AdminConfig | null>(null);
  const [failed, setFailed] = useState(false);
  const [ml, setMl] = useState<MlStatus | null>(null);
  const [metrics, setMetrics] = useState<MetricsBody | null>(null);
  const [dataset, setDataset] = useState<MlDataset | null>(null);
  const [evaluation, setEvaluation] = useState<EvaluationReport | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const [correlation, setCorrelation] = useState<CorrelationStatus | null>(null);
  const [containment, setContainment] = useState<ContainmentBody | null>(null);
  const [notifications, setNotifications] = useState<NotificationsBody | null>(null);
  const [compliance, setCompliance] = useState<ComplianceBody | null>(null);
  const [audit, setAudit] = useState<AuditBody | null>(null);
  const [suppression, setSuppression] = useState<SuppressionBody | null>(null);
  const [draft, setDraft] = useState<ProposedRule>(EMPTY_RULE);
  const [operationsError, setOperationsError] = useState("");
  const [actionNotice, setActionNotice] = useState("");
  const [actionError, setActionError] = useState("");
  const [blockIp, setBlockIp] = useState("");
  const [blockMinutes, setBlockMinutes] = useState("30");
  const [blockReason, setBlockReason] = useState("");
  const [notifyPassword, setNotifyPassword] = useState("");
  const [retentionMinutes, setRetentionMinutes] = useState("");
  const [retentionPassword, setRetentionPassword] = useState("");
  const [sweepNow, setSweepNow] = useState(true);
  const [bundle, setBundle] = useState<EvidenceBundle | null>(null);
  const allowed = canSeeAdmin(role);

  const refreshOperations = useCallback(async () => {
    try {
      const [mlBody, correlationBody, containmentBody, notificationBody, complianceBody, auditBody, ruleBody, datasetBody, metricsBody] =
        await Promise.all([
          loadMlStatus(),
          loadCorrelationStatus(),
          loadContainment(),
          loadNotifications(),
          loadCompliance(),
          loadAudit(),
          loadSuppressionRules(),
          loadMlDataset(),
          loadMetrics(),
        ]);
      setMl(mlBody);
      setDataset(datasetBody);
      setMetrics(metricsBody);
      setCorrelation(correlationBody);
      setContainment(containmentBody);
      setNotifications(notificationBody);
      setCompliance(complianceBody);
      setAudit(auditBody);
      setSuppression(ruleBody);
      setOperationsError("");
    } catch {
      setOperationsError("Some operations endpoints are unavailable.");
    }
  }, []);

  useEffect(() => {
    if (!allowed) return;
    readJson<AdminConfig>("/api/config")
      .then(setConfig)
      .catch(() => setFailed(true));
    refreshOperations();
  }, [allowed, refreshOperations]);

  useEffect(() => {
    if (compliance && retentionMinutes === "") {
      setRetentionMinutes(String(compliance.retentionMinutes));
    }
  }, [compliance, retentionMinutes]);

  if (!allowed) {
    return <p>{accessDenied(role)}</p>;
  }

  async function block(event: FormEvent) {
    event.preventDefault();
    setActionError("");
    setActionNotice("");
    const ip = blockIp.trim();
    const minutes = Math.max(1, Number(blockMinutes) || 30);
    try {
      await containSource(ip, minutes, blockReason.trim());
      setActionNotice(`Contained ${ip} for ${minutes} minutes.`);
      setBlockIp("");
      setBlockReason("");
      await refreshOperations();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 409) {
        setActionError("The server refused the block. Containment may be off, or a safeguard refused it.");
      } else if (error instanceof HttpStatusError && error.status === 400) {
        setActionError("Enter an address and a positive duration.");
      } else {
        setActionError("The block request failed.");
      }
    }
  }

  async function release(ip: string) {
    setActionError("");
    setActionNotice("");
    try {
      await releaseSource(ip);
      setActionNotice(`Released ${ip}.`);
      await refreshOperations();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 404) {
        setActionError(`${ip} is not blocked.`);
      } else {
        setActionError("The release request failed.");
      }
    }
  }

  async function createSuppression(event: FormEvent) {
    event.preventDefault();
    setActionError("");
    setActionNotice("");
    try {
      const rule = await addSuppressionRule(draft);
      setActionNotice(`Rule ${rule.id} created: ${rule.describe}.`);
      setDraft(EMPTY_RULE);
      await refreshOperations();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 400) {
        setActionError("A rule has to name at least one field, and the table has a size limit.");
      } else if (error instanceof HttpStatusError && error.status === 403) {
        setActionError("This role cannot change suppression rules.");
      } else {
        setActionError("The rule could not be created.");
      }
    }
  }

  async function deleteSuppression(id: string) {
    setActionError("");
    setActionNotice("");
    try {
      await removeSuppressionRule(id);
      setActionNotice(`Rule ${id} removed.`);
      await refreshOperations();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 404) {
        setActionError(`${id} is not in the table.`);
      } else {
        setActionError("The rule could not be removed.");
      }
    }
  }

  async function writeBundle() {
    setActionError("");
    setActionNotice("");
    try {
      const body = await exportEvidence();
      setBundle(body);
      setActionNotice(`Evidence bundle written to ${body.directory}.`);
      await refreshOperations();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 409) {
        setActionError("Evidence export is off on this server. Set forensics.enabled=true to use it.");
      } else {
        setActionError("The export failed.");
      }
    }
  }

  async function runNotificationTest() {
    setActionError("");
    setActionNotice("");
    try {
      const { deliveries } = await testNotifications();
      const summary = deliveries.map((row) => `${row.channel} ${row.outcome}`).join(", ");
      setActionNotice(`Notification test: ${summary}.`);
      await refreshOperations();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 403) {
        setActionError("Only an administrator can test delivery.");
      } else {
        setActionError("The notification test failed.");
      }
    }
  }

  async function toggleNotifications(next: boolean) {
    setActionError("");
    setActionNotice("");
    try {
      await setNotificationsEnabled(next, notifyPassword);
      setNotifyPassword("");
      setActionNotice(`Delivery ${next ? "enabled" : "disabled"}.`);
      await refreshOperations();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 401) {
        setActionError("The server did not accept the password.");
      } else {
        setActionError("The delivery switch could not be changed.");
      }
    }
  }

  async function applyRetention(event: FormEvent) {
    event.preventDefault();
    setActionError("");
    setActionNotice("");
    const minutes = Number(retentionMinutes);
    if (!Number.isFinite(minutes) || minutes < 5) {
      setActionError("Retention must be at least 5 minutes.");
      return;
    }
    try {
      const result = await setRetention(minutes, retentionPassword, sweepNow);
      setRetentionPassword("");
      setActionNotice(
        `Retention is now ${result.retentionMinutes} minutes` +
          (result.sweptRows > 0 ? `, ${result.sweptRows} rows swept.` : "."),
      );
      await refreshOperations();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 401) {
        setActionError("The server did not accept the password.");
      } else if (error instanceof HttpStatusError && error.status === 400) {
        setActionError("Retention must be between 5 minutes and 10 years.");
      } else {
        setActionError("Retention could not be changed.");
      }
    }
  }

  async function runEvaluation() {
    setActionError("");
    setActionNotice("");
    setEvaluating(true);
    try {
      const report = await evaluateModel();
      setEvaluation(report);
      setActionNotice(
        report.available
          ? `Evaluated ${report.samples} labelled flows from ${report.runs.length} runs.`
          : report.reason,
      );
      await refreshOperations();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 403) {
        setActionError("This role cannot run an evaluation.");
      } else {
        setActionError("The evaluation request failed.");
      }
    } finally {
      setEvaluating(false);
    }
  }

  return (
    <Page
      title="Admin"
      description="Read only view of the detector thresholds, session policy, accounts, and the state of the newer pipeline capabilities."
    >
      {failed ? <EmptyState>The configuration endpoint is unavailable.</EmptyState> : null}
      {operationsError ? <p className="notice">{operationsError}</p> : null}
      {actionNotice ? <p className="notice">{actionNotice}</p> : null}
      {actionError ? <p className="notice">{actionError}</p> : null}

      <Panel
        title="Operations status"
        subtitle="Each number is read from the component that owns it."
        action={<button type="button" className="secondary" onClick={() => refreshOperations()}>Refresh</button>}
      >
        {!ml && !correlation && !containment && !notifications ? (
          <EmptyState>Loading operations status.</EmptyState>
        ) : (
          <table>
            <thead>
              <tr><th>Component</th><th>State</th><th>Detail</th></tr>
            </thead>
            <tbody>
              <tr>
                <td>Flow model</td>
                <td>{ml ? <StatusBadge status={ml.enabled ? ml.modelState : "OFF"} /> : "n/a"}</td>
                <td>
                  {ml
                    ? `${ml.samples} samples, ${ml.clusters} clusters, threshold ${ml.threshold}, ` +
                      `${ml.scored} scored, ${ml.anomalies} anomalies, ${ml.alerts} alerts, ` +
                      `${ml.excluded} excluded from training`
                    : "n/a"}
                </td>
              </tr>
              <tr>
                <td>Correlation</td>
                <td>{correlation ? <StatusBadge status={correlation.enabled ? "ON" : "OFF"} /> : "n/a"}</td>
                <td>
                  {correlation
                    ? `${correlation.correlated} correlated from ${correlation.signals} signals, ` +
                      `${correlation.minSignals} signal minimum, ${correlation.windowSeconds}s window`
                    : "n/a"}
                </td>
              </tr>
              <tr>
                <td>Kill chains</td>
                <td>
                  {correlation
                    ? <StatusBadge status={correlation.chains ? (correlation.chainsMatched ?? 0) > 0 ? "ON" : "ARMED" : "OFF"} />
                    : "n/a"}
                </td>
                <td>
                  {correlation
                    ? correlation.chainProblem
                      ? `Problem: ${correlation.chainProblem}`
                      : `${correlation.chains ?? 0} rules, ${correlation.chainsMatched ?? 0} matched, ` +
                        `last ${correlation.lastChain ?? "none"}`
                    : "n/a"}
                </td>
              </tr>
              <tr>
                <td>Containment</td>
                <td>{containment ? <StatusBadge status={containment.mode} /> : "n/a"}</td>
                <td>
                  {containment
                    ? `${containment.blocked.length} blocked, ${containment.droppedEvents} events dropped, ` +
                      `${containment.refusedActions} refused by a safeguard`
                    : "n/a"}
                </td>
              </tr>
              <tr>
                <td>Pipeline metrics</td>
                <td>{metrics ? <StatusBadge status="LIVE" /> : "n/a"}</td>
                <td>
                  {metrics
                    ? `${metrics.processedEvents.toLocaleString()} events processed, ${metrics.queueDepth} queued, ` +
                      `${metrics.droppedEvents} dropped, ${metrics.detectedAlerts} detected, ` +
                      `${metrics.deliveredAlerts} delivered, ` +
                      `${metrics.storeEnabled ? `${metrics.writtenRows} rows written` : "store off"}, ` +
                      `${megabytes(metrics.heapUsedBytes)} heap, up ${uptime(metrics.uptimeSeconds)}`
                    : "n/a"}
                </td>
              </tr>
              <tr>
                <td>Notifications</td>
                <td>{notifications ? <StatusBadge status={notifications.enabled ? "ON" : "OFF"} /> : "n/a"}</td>
                <td>
                  {notifications
                    ? `${notifications.recorded} recorded, ${notifications.webhookSent} sent, ` +
                      `${notifications.webhookFailed} failed, ${notifications.dropped} dropped`
                    : "n/a"}
                </td>
              </tr>
            </tbody>
          </table>
        )}
      </Panel>

      <Panel
        title="Model evaluation"
        subtitle="The only ground truth this system sees is the label file beside an imported capture. The rules and the model are scored on the same labelled flows, and the model never trained on the flows that alerted."
        action={
          <button
            type="button"
            onClick={() => runEvaluation()}
            disabled={evaluating || !dataset || dataset.samples === 0}
          >
            {evaluating ? "Evaluating" : "Run evaluation"}
          </button>
        }
      >
        <p className="muted">
          {dataset
            ? `${dataset.samples} labelled flows (${dataset.attackSamples} attack, ${dataset.benignSamples} benign) ` +
              `from ${dataset.runs} replay runs`
            : "Loading labelled flows."}
        </p>
        {dataset && dataset.samples === 0 ? (
          <EmptyState>
            No labelled flows yet. Import a capture with its label file first; the labels are what an evaluation is
            measured against.
          </EmptyState>
        ) : null}
        {evaluation ? (
          <>
            {!evaluation.available ? <p className="muted">{evaluation.reason}</p> : null}
            {evaluation.rules ? (
              <table>
                <thead>
                  <tr>
                    <th>Verdict</th><th>Precision</th><th>Recall</th><th>F1</th><th>False positive rate</th><th>Accuracy</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Model at threshold {evaluation.threshold}</td>
                    {scoreCells(evaluation.chosen)}
                  </tr>
                  <tr>
                    <td>Best F1 in the sweep{evaluation.best ? ` (threshold ${evaluation.best.threshold})` : ""}</td>
                    {scoreCells(evaluation.best)}
                  </tr>
                  <tr>
                    <td>Rule detectors ({evaluation.rules.alerted} alerted)</td>
                    {scoreCells(evaluation.rules)}
                  </tr>
                </tbody>
              </table>
            ) : null}
            <p className="muted">In-sample: these flows were also used for training.</p>
            {evaluation.sweep.length > 0 ? (
              <>
                <p className="muted">Threshold sweep on the same rows.</p>
                <table>
                  <thead>
                    <tr><th>Threshold</th><th>Precision</th><th>Recall</th><th>F1</th><th>False positive rate</th><th>Accuracy</th></tr>
                  </thead>
                  <tbody>
                    {evaluation.sweep.map((point) => (
                      <tr key={point.threshold}>
                        <td className="mono">{point.threshold}</td>
                        {scoreCells(point)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            ) : null}
            {evaluation.runs.length > 0 ? (
              <>
                <p className="muted">Per replay run, so an aggregate cannot hide one bad capture.</p>
                <table>
                  <thead>
                    <tr><th>Run</th><th>Source</th><th>Flows</th><th>Attack</th><th>Model F1</th><th>Rules F1</th></tr>
                  </thead>
                  <tbody>
                    {evaluation.runs.map((run) => (
                      <tr key={run.id}>
                        <td className="mono">{run.id}</td>
                        <td>{run.source}</td>
                        <td>{run.samples}</td>
                        <td>{run.attackSamples}</td>
                        <td>{run.point ? ratio(run.point.f1) : "n/a"}</td>
                        <td>{ratio(run.rules.f1)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            ) : null}
            <p className="muted">{evaluation.note}</p>
          </>
        ) : (
          <EmptyState>No evaluation run yet. The button scores the retained labelled flows against the live model.</EmptyState>
        )}
      </Panel>

      <Panel title="Containment" subtitle="Blocks expire. Every action names the account that asked for it. The mode is set on the Control page.">
        {containment && !containment.enabled ? (
          <EmptyState>Containment is off. Switch the mode to IDS or IPS on the Control page to record blocks.</EmptyState>
        ) : null}
        {containment && containment.mode === "IDS" ? (
          <p className="muted">
            The mode is IDS, so blocks are recorded and audited but traffic keeps flowing.
          </p>
        ) : null}
        <form className="row" onSubmit={block}>
          <input
            aria-label="Address to contain"
            placeholder="Source address"
            value={blockIp}
            onChange={(event) => setBlockIp(event.target.value)}
          />
          <input
            aria-label="Minutes"
            type="number"
            min={1}
            value={blockMinutes}
            onChange={(event) => setBlockMinutes(event.target.value)}
          />
          <input
            aria-label="Reason"
            placeholder="Reason"
            value={blockReason}
            onChange={(event) => setBlockReason(event.target.value)}
          />
          <button type="submit" disabled={blockIp.trim().length === 0}>Block</button>
        </form>
        {containment && containment.blocked.length > 0 ? (
          <table>
            <thead>
              <tr><th>Address</th><th>Expires</th><th>Reason</th><th>Actor</th><th /></tr>
            </thead>
            <tbody>
              {containment.blocked.map((entry) => (
                <tr key={entry.ip}>
                  <td className="mono">{entry.ip}</td>
                  <td className="mono">{clockTime(entry.expiresAt)}</td>
                  <td>{entry.automatic ? `Auto: ${entry.reason}` : entry.reason || "not stated"}</td>
                  <td>{entry.actor || "unknown"}</td>
                  <td>
                    <button type="button" className="secondary" onClick={() => release(entry.ip)}>
                      Release
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState>No addresses are contained.</EmptyState>
        )}
      </Panel>

      <Panel
        title="Suppression rules"
        subtitle="Blank fields are wildcards. A rule only ever narrows, and its severity is a ceiling, so a low rule cannot silence a critical alert."
      >
        {suppression && !suppression.enabled ? (
          <EmptyState>Suppression is off. Set suppression.enabled=true to apply these rules.</EmptyState>
        ) : null}
        <form className="row" onSubmit={createSuppression}>
          <input
            aria-label="Detector"
            placeholder="Detector"
            value={draft.detector}
            onChange={(event) => setDraft({ ...draft, detector: event.target.value })}
          />
          <input
            aria-label="Attack type"
            placeholder="Attack type"
            value={draft.attackType}
            onChange={(event) => setDraft({ ...draft, attackType: event.target.value })}
          />
          <input
            aria-label="Source address"
            placeholder="Source"
            value={draft.sourceIp}
            onChange={(event) => setDraft({ ...draft, sourceIp: event.target.value })}
          />
          <input
            aria-label="Target address"
            placeholder="Target"
            value={draft.targetIp}
            onChange={(event) => setDraft({ ...draft, targetIp: event.target.value })}
          />
          <select
            aria-label="Severity ceiling"
            value={draft.maxSeverity}
            onChange={(event) => setDraft({ ...draft, maxSeverity: event.target.value })}
          >
            <option value="">Any severity</option>
            <option value="LOW">Low or below</option>
            <option value="HIGH">High or below</option>
            <option value="CRITICAL">Critical or below</option>
          </select>
          <input
            aria-label="Note"
            placeholder="Why"
            value={draft.note}
            onChange={(event) => setDraft({ ...draft, note: event.target.value })}
          />
          <button type="submit">Add rule</button>
        </form>
        {!suppression || suppression.rules.length === 0 ? (
          <EmptyState>No suppression rules. Every detector outcome reaches the feed.</EmptyState>
        ) : (
          <table>
            <thead>
              <tr><th>Rule</th><th>Match</th><th>Why</th><th>By</th><th /></tr>
            </thead>
            <tbody>
              {suppression.rules.map((rule) => (
                <tr key={rule.id}>
                  <td className="mono">{rule.id}</td>
                  <td>{rule.describe}</td>
                  <td>{rule.note || "not stated"}</td>
                  <td>{rule.createdBy || "unknown"}</td>
                  <td>
                    <button type="button" className="secondary" onClick={() => void deleteSuppression(rule.id)}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {suppression ? (
          <p className="muted">
            {suppression.count} rules kept in <span className="mono">{suppression.file || "memory only"}</span>.
          </p>
        ) : null}
      </Panel>

      <Panel
        title="Notifications"
        subtitle="The outbox stays on this machine; the console, the email relay and the webhook are separate channels."
        action={
          <button type="button" className="secondary" onClick={() => runNotificationTest()} disabled={!notifications}>
            Send test
          </button>
        }
      >
        {!notifications ? (
          <EmptyState>Loading delivery status.</EmptyState>
        ) : (
          <>
            <table>
              <thead>
                <tr><th>Item</th><th>Value</th></tr>
              </thead>
              <tbody>
                <tr>
                  <td>Delivery</td>
                  <td><StatusBadge status={notifications.enabled ? "ON" : "OFF"} /></td>
                </tr>
                <tr>
                  <td>Floor</td>
                  <td>
                    {notifications.minimumSeverity} and above: {notifications.recorded} recorded,{" "}
                    {notifications.health.suppressed} below the floor, {notifications.dropped} dropped
                  </td>
                </tr>
                <tr>
                  <td>Channels</td>
                  <td>
                    console {notifications.health.console ? "on" : "off"}, email{" "}
                    {notifications.health.email ? notifications.health.emailRecipient || "on" : "off"}, webhook{" "}
                    {notifications.health.webhookRefusal
                      ? `refused: ${notifications.health.webhookRefusal}`
                      : notifications.health.webhookHost || "not configured"}
                  </td>
                </tr>
                <tr>
                  <td>Retry and limits</td>
                  <td>
                    {notifications.settings.retries} retries with {notifications.settings.backoffMillis} ms backoff,{" "}
                    breaker after {notifications.settings.breakerThreshold} failures for{" "}
                    {notifications.settings.breakerCooldownSeconds} s, {notifications.settings.maxPerHour} per hour,{" "}
                    {notifications.settings.cooldownSeconds} s per source cooldown
                  </td>
                </tr>
                <tr>
                  <td>Guards</td>
                  <td>
                    {notifications.settings.allowInsecure ? "loopback http allowed" : "https only"},{" "}
                    {notifications.settings.redact ? "redaction on" : "redaction off"}, body capped at{" "}
                    {notifications.settings.maxBodyBytes} bytes
                  </td>
                </tr>
                <tr>
                  <td>Delivery health</td>
                  <td>
                    {notifications.health.breakerOpen
                      ? `circuit open until ${relativeTime(notifications.health.breakerUntil)}`
                      : `${notifications.health.consecutiveFailures} consecutive failures`}
                    , {notifications.health.rateLimited} rate limited,{" "}
                    {notifications.health.cooldownSkipped} on cooldown, {notifications.health.refused} refused
                  </td>
                </tr>
                {notifications.lastError ? (
                  <tr>
                    <td>Last error</td>
                    <td className="mono">{notifications.lastError}</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
            <form
              className="row"
              onSubmit={(event) => {
                event.preventDefault();
                toggleNotifications(!notifications.enabled);
              }}
            >
              <input
                aria-label="Password for the delivery switch"
                type="password"
                placeholder="Password"
                value={notifyPassword}
                onChange={(event) => setNotifyPassword(event.target.value)}
              />
              <button type="submit" disabled={notifyPassword.length === 0}>
                {notifications.enabled ? "Disable delivery" : "Enable delivery"}
              </button>
            </form>
            <p className="muted">Delivery history, newest first.</p>
            {notifications.deliveries.length === 0 ? (
              <EmptyState>No delivery attempts recorded.</EmptyState>
            ) : (
              <table>
                <thead>
                  <tr><th>When</th><th>Channel</th><th>Outcome</th><th>Attempts</th><th>Detail</th></tr>
                </thead>
                <tbody>
                  {notifications.deliveries.slice(0, 10).map((row, index) => (
                    <tr key={`${row.at}-${row.channel}-${index}`}>
                      <td className="mono" title={row.at}>{relativeTime(row.at)}</td>
                      <td>{row.channel}</td>
                      <td><StatusBadge status={row.outcome} /></td>
                      <td>{row.attempts}</td>
                      <td>{row.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <p className="muted">Alerts recorded in the outbox, newest first.</p>
            {notifications.notifications.length === 0 ? (
              <EmptyState>No notifications recorded.</EmptyState>
            ) : (
              <table>
                <thead>
                  <tr><th>When</th><th>Severity</th><th>Channel</th><th>Summary</th></tr>
                </thead>
                <tbody>
                  {notifications.notifications.slice(0, 10).map((row) => (
                    <tr key={row.id}>
                      <td className="mono" title={row.timestamp}>{relativeTime(row.timestamp)}</td>
                      <td><StatusBadge status={row.severity} /></td>
                      <td>{row.escalation ? `${row.channel} (escalation)` : row.channel}</td>
                      <td>{row.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </Panel>

      <Panel
        title="Compliance and evidence"
        subtitle="What is retained, for how long, and what privileged actions were recorded."
        action={
          <button type="button" onClick={() => writeBundle()} disabled={!compliance?.forensicsEnabled}>
            Export bundle
          </button>
        }
      >
        {compliance ? (
          <>
            <table>
              <thead>
                <tr><th>Item</th><th>Value</th></tr>
              </thead>
              <tbody>
                <tr><td>Durable store</td><td>{compliance.storeEnabled ? compliance.databasePath : "off"}</td></tr>
                <tr><td>Stored rows</td><td>{compliance.storedFlows} flows, {compliance.storedAlerts} alerts</td></tr>
                <tr><td>Retention</td><td>{compliance.retentionMinutes} minutes, cutoff {compliance.retentionCutoff}</td></tr>
                <tr><td>Retention sweep</td><td>every {compliance.sweepMinutes} minutes</td></tr>
                <tr>
                  <td>Audit trail</td>
                  <td>
                    {compliance.auditRecords} of {compliance.auditCapacity} entries,{" "}
                    {compliance.auditDenied} denied, {compliance.auditFailed} failed
                  </td>
                </tr>
                <tr><td>Containment</td><td>{compliance.containedSources} sources blocked</td></tr>
                <tr><td>Evidence directory</td><td className="mono">{compliance.evidenceDirectory}</td></tr>
              </tbody>
            </table>
            <p className="muted">{compliance.mappingNote}</p>
            <table>
              <thead>
                <tr><th>Control</th><th>Status</th><th>Evidence</th></tr>
              </thead>
              <tbody>
                {compliance.controls.map((control) => (
                  <tr key={control.id}>
                    <td>{control.id} {control.title}</td>
                    <td><StatusBadge status={control.status} /></td>
                    <td>{control.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        ) : (
          <EmptyState>Loading compliance summary.</EmptyState>
        )}
        {bundle ? (
          <p className="muted">
            Last bundle: {bundle.files} files, {bundle.bytes} bytes, manifest {bundle.manifestSha256.slice(0, 16)}.
          </p>
        ) : null}
      </Panel>

      <Panel
        title="Retention"
        subtitle="How long the store keeps rows. A change is validated, audited and followed by a sweep."
      >
        <p className="muted">
          Current: {compliance ? `${compliance.retentionMinutes} minutes` : "unknown"}, swept every{" "}
          {compliance ? `${compliance.sweepMinutes} minutes` : "unknown"}.
        </p>
        <form className="row" onSubmit={applyRetention}>
          <input
            aria-label="Retention in minutes"
            type="number"
            min={5}
            value={retentionMinutes}
            onChange={(event) => setRetentionMinutes(event.target.value)}
          />
          <input
            aria-label="Password for the retention change"
            type="password"
            placeholder="Password"
            value={retentionPassword}
            onChange={(event) => setRetentionPassword(event.target.value)}
          />
          <label className="muted">
            <input type="checkbox" checked={sweepNow} onChange={(event) => setSweepNow(event.target.checked)} />
            {" "}sweep now
          </label>
          <button type="submit" disabled={retentionPassword.length === 0}>Apply</button>
        </form>
      </Panel>

      <Panel title="Audit trail" subtitle="Newest first. This is the answer to who asked for what.">
        {!audit || audit.entries.length === 0 ? (
          <EmptyState>No audited actions yet.</EmptyState>
        ) : (
          <table>
            <thead>
              <tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th></tr>
            </thead>
            <tbody>
              {audit.entries.slice(0, 15).map((entry) => (
                <tr key={entry.sequence}>
                  <td className="mono" title={entry.timestamp}>{relativeTime(entry.timestamp)}</td>
                  <td>{entry.actor}</td>
                  <td>{entry.action}</td>
                  <td className="mono">{entry.target}</td>
                  <td><StatusBadge status={entry.outcome} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <IntelPanel />
      <Panel title="Detector thresholds">
        {config ? (
          <table>
            <thead>
              <tr><th>Setting</th><th>Value</th></tr>
            </thead>
            <tbody>
              {Object.entries(config.thresholds).map(([key, value]) => (
                <tr key={key}><td>{key}</td><td>{value}</td></tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState>Loading configuration.</EmptyState>
        )}
      </Panel>
      <Panel
        title="Simulation noise"
        subtitle="Off by default. Backups, retries and high ports make ordinary traffic look unusual, and a share of injected attacks takes a shape the rules were not written for."
      >
        {config?.simulation ? (
          <table>
            <thead>
              <tr><th>Setting</th><th>Value</th></tr>
            </thead>
            <tbody>
              <tr>
                <td>Noise</td>
                <td><StatusBadge status={config.simulation.noiseEnabled ? "ON" : "OFF"} /></td>
              </tr>
              <tr><td>Benign backup chance</td><td>{ratio(config.simulation.benignSpikeChance)}</td></tr>
              <tr><td>Benign retry chance</td><td>{ratio(config.simulation.retryChance)}</td></tr>
              <tr><td>Uncommon port chance</td><td>{ratio(config.simulation.portSpreadChance)}</td></tr>
              <tr><td>Attack variant chance</td><td>{ratio(config.simulation.attackVariantChance)}</td></tr>
            </tbody>
          </table>
        ) : (
          <EmptyState>Loading simulation settings.</EmptyState>
        )}
      </Panel>
      <Panel title="Session policy">
        {config ? (
          <table>
            <thead>
              <tr><th>Setting</th><th>Value</th></tr>
            </thead>
            <tbody>
              <tr><td>Session timeout</td><td>{config.session.timeoutSeconds} seconds</td></tr>
              <tr>
                <td>Absolute session lifetime</td>
                <td>
                  {config.session.absoluteTimeoutSeconds
                    ? `${config.session.absoluteTimeoutSeconds} seconds from sign-in`
                    : "not limited"}
                </td>
              </tr>
              <tr>
                <td>Password repeated for serious actions</td>
                <td>
                  {config.session.reauthEnabled
                    ? `yes, valid for ${config.session.reauthFreshSeconds} seconds`
                    : "no"}
                </td>
              </tr>
              <tr><td>CSRF token required</td><td>{config.session.csrfEnabled ? "yes" : "no"}</td></tr>
              <tr><td>Login attempts before lockout</td><td>{config.session.loginMaxAttempts}</td></tr>
              <tr><td>Lockout window</td><td>{config.session.loginWindowSeconds} seconds</td></tr>
            </tbody>
          </table>
        ) : (
          <EmptyState>Loading session policy.</EmptyState>
        )}
      </Panel>
      <Panel title="Accounts" subtitle="Passwords are stored as PBKDF2 hashes and never returned by the API.">
        {config ? (
          <table>
            <thead>
              <tr><th>Username</th><th>Role</th></tr>
            </thead>
            <tbody>
              {config.accounts.map((account) => (
                <tr key={account.role}><td>{account.username}</td><td>{account.role}</td></tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState>Loading accounts.</EmptyState>
        )}
      </Panel>
    </Page>
  );
}

function IntelPanel() {
  const [status, setStatus] = useState<IntelStatus | null>(null);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    loadIntelStatus()
      .then((body) => {
        if (!cancelled) setStatus(body);
      })
      .catch(() => {
        if (!cancelled) setMessage("The intel endpoint is unavailable.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function reload(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const body = await reloadIntel(password);
      setStatus(body);
      setPassword("");
      setMessage(`Feed reloaded: ${body.entries} indicators from ${body.source}.`);
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 401) {
        setMessage("The server did not accept the password.");
      } else if (error instanceof HttpStatusError && error.status === 422) {
        setMessage("The feed could not be read, so the previous one is still in use.");
      } else if (error instanceof HttpStatusError && error.status === 403) {
        setMessage("Only an Admin can reload the feed.");
      } else {
        setMessage("The reload request failed.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      title="Threat intel"
      subtitle="Indicators are matched on the source address and on the payload. An expired entry never matches, and a reload swaps the feed without a restart."
    >
      {status ? (
        <div className="table-scroll">
          <table className="intel-table">
            <tbody>
              <tr><th>Feed</th><td className="mono">{status.feed}</td></tr>
              <tr><th>Detector</th><td>{status.enabled ? "on" : "off"}</td></tr>
              <tr>
                <th>Indicators</th>
                <td>
                  {status.entries} ({status.addresses} addresses, {status.domains} domains, {status.digests} digests)
                </td>
              </tr>
              <tr><th>Skipped</th><td>{status.skipped}</td></tr>
              <tr><th>Expired</th><td>{status.expired}</td></tr>
              <tr><th>Last reload</th><td>{status.lastReloadAt ?? "not reloaded in this session"}</td></tr>
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState>Loading the feed.</EmptyState>
      )}
      <form className="row intel-form" onSubmit={reload}>
        <label className="intel-password-label">
          Password{" "}
          <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
        </label>
        <button type="submit" className="secondary" disabled={busy || password.length === 0}>
          Reload feed
        </button>
      </form>
      {message ? <p className="notice">{message}</p> : null}
    </Panel>
  );
}
