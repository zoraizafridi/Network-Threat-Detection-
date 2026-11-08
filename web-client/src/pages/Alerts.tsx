import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { filterAlerts, foldLabel, type FeedAlert } from "../alerts";
import {
  HttpStatusError,
  addSuppressionRule,
  setAlertStatus,
  type ProposedRule,
  type SuppressionRule,
} from "../api";
import { attackLabel, clockTime } from "../format";
import { EmptyState, MapPanel, Page, Panel, StatusBadge } from "../components/ui";
import { NetworkMap } from "../components/NetworkMap";
import { accessDenied, canLaunchAttack } from "../permissions";
import { useApp } from "../store";

const MOVES: { value: string; label: string }[] = [
  { value: "ACKNOWLEDGED", label: "Acknowledge" },
  { value: "INVESTIGATING", label: "Investigate" },
  { value: "RESOLVED", label: "Resolve" },
  { value: "NEW", label: "Reopen" },
];

export function AlertsPage() {
  const role = useApp((state) => state.user?.role ?? "");
  const alerts = useApp((state) => state.alerts);
  const assets = useApp((state) => state.assets);
  const setAlerts = useApp((state) => state.setAlerts);
  const setSelectedId = useApp((state) => state.setSelectedId);
  const setNotice = useApp((state) => state.setNotice);
  const navigate = useNavigate();
  const [severity, setSeverity] = useState("");
  const [attackType, setAttackType] = useState("");
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [proposal, setProposal] = useState<{ alert: FeedAlert; rule: ProposedRule } | null>(null);
  const [created, setCreated] = useState<SuppressionRule | null>(null);
  const canTriage = canLaunchAttack(role);
  const rows = useMemo(
    () => filterAlerts(alerts, { severity, attackType, source, target }).slice().reverse(),
    [alerts, severity, attackType, source, target],
  );

  function focus(ip: string) {
    const host = assets.find((asset) => asset.ip === ip);
    if (!host) return;
    setSelectedId(host.id);
    navigate("/portal");
  }

  function replace(row: FeedAlert) {
    setAlerts(alerts.map((item) => (item.id === row.id ? { ...item, ...row } : item)));
  }

  async function move(row: FeedAlert, status: string) {
    setNotice("");
    try {
      const body = await setAlertStatus(row.id, status);
      replace(body.alert);
      if (status === "FALSE_POSITIVE" && body.proposedRule) {
        setProposal({ alert: body.alert, rule: body.proposedRule });
      }
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 403) setNotice(accessDenied(role));
      else if (error instanceof HttpStatusError && error.status === 409) setNotice("That move would skip triage.");
      else if (error instanceof HttpStatusError && error.status === 404) setNotice("That alert is no longer in the live feed.");
      else setNotice("The status change failed.");
    }
  }

  async function createRule() {
    if (!proposal) return;
    setNotice("");
    try {
      const rule = await addSuppressionRule(proposal.rule);
      setCreated(rule);
      setProposal(null);
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 400) setNotice("That rule names nothing to suppress.");
      else if (error instanceof HttpStatusError && error.status === 403) setNotice(accessDenied(role));
      else setNotice("The rule could not be created.");
    }
  }

  return (
    <Page title="Alerts" description="One row per detected fact. Repeats fold into the first sighting and show their count.">
      <div className="row">
        <select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Severity">
          <option value="">All severities</option>
          <option value="LOW">Low</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
        <select value={attackType} onChange={(event) => setAttackType(event.target.value)} aria-label="Type">
          <option value="">All types</option>
          <option value="PORT_SCAN">Port scan</option>
          <option value="BRUTE_FORCE">Brute force</option>
          <option value="DOS_FLOOD">DoS flood</option>
          <option value="DATA_TRANSFER">Data transfer</option>
        </select>
        <input value={source} onChange={(event) => setSource(event.target.value)} aria-label="Source" placeholder="Source" />
        <input value={target} onChange={(event) => setTarget(event.target.value)} aria-label="Target" placeholder="Target" />
      </div>

      {proposal ? (
        <Panel
          title="Proposed suppression rule"
          subtitle="A false positive suggests the rule it would take to silence this route. Creating it is a separate, audited decision."
          action={<button type="button" className="secondary" onClick={() => setProposal(null)}>Discard</button>}
        >
          <p className="muted">{describeRule(proposal.rule)}</p>
          <button type="button" className="primary" onClick={() => void createRule()} disabled={!canTriage}>
            Create rule
          </button>
        </Panel>
      ) : null}
      {created ? (
        <p className="notice">
          Rule {created.id} created: {created.describe}. It applies from the next alert.
        </p>
      ) : null}

      <div className="board-12">
        <Panel className="span-8" title="Alert list" subtitle="Newest first. Click a row to focus the host">
          {rows.length === 0 ? <EmptyState>No alerts match these filters.</EmptyState> : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Source</th>
                <th>Target</th>
                <th>Count</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((alert) => (
                <tr key={alert.id} onClick={() => focus(alert.targetIp)}>
                  <td className="mono" title={alert.timestamp}>{clockTime(alert.timestamp)}</td>
                  <td><StatusBadge status={alert.severity} /></td>
                  <td>
                    {attackLabel(alert.attackType)}{" "}
                    {alert.detectorName === "ThreatIntelDetector" ? <span className="sim-pill">IoC</span> : null}
                  </td>
                  <td>{alert.sourceIp}</td>
                  <td>{alert.targetIp}</td>
                  <td className="mono" title={alert.lastSeen ? `last seen ${alert.lastSeen}` : undefined}>
                    {foldLabel(alert)}
                  </td>
                  <td onClick={(event) => event.stopPropagation()}>
                    <StatusBadge status={alert.status ?? "NEW"} />
                    {canTriage ? (
                      <select
                        className="move-select"
                        aria-label={`Move alert ${alert.id}`}
                        value=""
                        onChange={(event) => {
                          const next = event.target.value;
                          event.target.value = "";
                          if (next) void move(alert, next);
                        }}
                      >
                        <option value="">Move</option>
                        {MOVES.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                        <option value="FALSE_POSITIVE">False positive</option>
                      </select>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          )}
        </Panel>
        <MapPanel className="span-4" title="Topology" subtitle="Same scene as Overview">
          <NetworkMap assets={assets} selectedId={null} onSelect={() => {}} />
        </MapPanel>
      </div>
    </Page>
  );
}

function describeRule(rule: ProposedRule): string {
  const parts = [
    `detector ${rule.detector || "any"}`,
    `type ${rule.attackType || "any"}`,
    `source ${rule.sourceIp || "any"}`,
    `target ${rule.targetIp || "any"}`,
    `at or below ${rule.maxSeverity || "any severity"}`,
  ];
  return parts.join(", ");
}
