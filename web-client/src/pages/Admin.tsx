import { useCallback, useEffect, useState, type FormEvent } from "react";
import { EmptyState, Page, Panel, StatusBadge } from "../components/ui";
import {
  HttpStatusError,
  containSource,
  exportEvidence,
  loadAudit,
  loadCompliance,
  loadContainment,
  loadCorrelationStatus,
  loadMlStatus,
  loadNotifications,
  readJson,
  releaseSource,
  type AuditBody,
  type ComplianceBody,
  type ContainmentBody,
  type CorrelationStatus,
  type EvidenceBundle,
  type MlStatus,
  type NotificationsBody,
} from "../api";
import { clockTime, relativeTime } from "../format";
import { accessDenied, canSeeAdmin } from "../permissions";
import { useApp } from "../store";

interface AdminConfig {
  thresholds: Record<string, string>;
  session: {
    timeoutSeconds: number;
    csrfEnabled: boolean;
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
  const [correlation, setCorrelation] = useState<CorrelationStatus | null>(null);
  const [containment, setContainment] = useState<ContainmentBody | null>(null);
  const [notifications, setNotifications] = useState<NotificationsBody | null>(null);
  const [compliance, setCompliance] = useState<ComplianceBody | null>(null);
  const [audit, setAudit] = useState<AuditBody | null>(null);
  const [operationsError, setOperationsError] = useState("");
  const [actionNotice, setActionNotice] = useState("");
  const [actionError, setActionError] = useState("");
  const [blockIp, setBlockIp] = useState("");
  const [blockMinutes, setBlockMinutes] = useState("30");
  const [blockReason, setBlockReason] = useState("");
  const [bundle, setBundle] = useState<EvidenceBundle | null>(null);
  const allowed = canSeeAdmin(role);

  const refreshOperations = useCallback(async () => {
    try {
      const [mlBody, correlationBody, containmentBody, notificationBody, complianceBody, auditBody] =
        await Promise.all([
          loadMlStatus(),
          loadCorrelationStatus(),
          loadContainment(),
          loadNotifications(),
          loadCompliance(),
          loadAudit(),
        ]);
      setMl(mlBody);
      setCorrelation(correlationBody);
      setContainment(containmentBody);
      setNotifications(notificationBody);
      setCompliance(complianceBody);
      setAudit(auditBody);
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
        setActionError("Containment is off on this server. Set containment.enabled=true to use it.");
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
                      `${ml.scored} scored, ${ml.anomalies} anomalies, ${ml.alerts} alerts`
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
                <td>Containment</td>
                <td>{containment ? <StatusBadge status={containment.enabled ? "ON" : "OFF"} /> : "n/a"}</td>
                <td>
                  {containment
                    ? `${containment.blocked.length} blocked, enforcement ${containment.enforce ? "on" : "off"}, ` +
                      `${containment.droppedEvents} events dropped`
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

      <Panel title="Containment" subtitle="Blocks expire. Every action names the account that asked for it.">
        {containment && !containment.enabled ? (
          <EmptyState>Containment is off. Set containment.enabled=true to record blocks.</EmptyState>
        ) : null}
        {containment && containment.enabled && !containment.enforce ? (
          <p className="muted">
            Enforcement is off, so blocks are recorded and audited but traffic keeps flowing.
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

      <Panel title="Notifications" subtitle="The outbox the server keeps for alerts at or above its floor.">
        {!notifications || notifications.notifications.length === 0 ? (
          <EmptyState>No notifications recorded.</EmptyState>
        ) : (
          <table>
            <thead>
              <tr><th>When</th><th>Severity</th><th>Summary</th></tr>
            </thead>
            <tbody>
              {notifications.notifications.slice(0, 10).map((row) => (
                <tr key={row.id}>
                  <td className="mono" title={row.timestamp}>{relativeTime(row.timestamp)}</td>
                  <td><StatusBadge status={row.severity} /></td>
                  <td>{row.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
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
        ) : (
          <EmptyState>Loading compliance summary.</EmptyState>
        )}
        {bundle ? (
          <p className="muted">
            Last bundle: {bundle.files} files, {bundle.bytes} bytes, manifest {bundle.manifestSha256.slice(0, 16)}.
          </p>
        ) : null}
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
      <Panel title="Session policy">
        {config ? (
          <table>
            <thead>
              <tr><th>Setting</th><th>Value</th></tr>
            </thead>
            <tbody>
              <tr><td>Session timeout</td><td>{config.session.timeoutSeconds} seconds</td></tr>
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
