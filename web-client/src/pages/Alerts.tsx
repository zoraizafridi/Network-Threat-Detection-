import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { filterAlerts } from "../alerts";
import { attackLabel } from "../format";
import { EmptyState, MapPanel, Page, Panel, StatusBadge } from "../components/ui";
import { NetworkMap } from "../components/NetworkMap";
import { useApp } from "../store";
import type { Asset } from "../types";

export function AlertsPage() {
  const alerts = useApp((state) => state.alerts);
  const assets = useApp((state) => state.assets);
  const setSelectedId = useApp((state) => state.setSelectedId);
  const navigate = useNavigate();
  const [severity, setSeverity] = useState("");
  const [attackType, setAttackType] = useState("");
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const rows = useMemo(
    () => filterAlerts(alerts, { severity, attackType, source, target }),
    [alerts, severity, attackType, source, target],
  );

  function focus(ip: string) {
    const host = assets.find((asset) => asset.ip === ip);
    if (!host) return;
    setSelectedId(host.id);
    navigate("/portal");
  }

  return (
    <Page title="Alerts" description="Detector alerts from the live feed.">
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
      <div className="board-12">
        <Panel className="span-8" title="Alert list" subtitle="Click a row to focus the host">
          {rows.length === 0 ? <EmptyState>No alerts match these filters.</EmptyState> : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Source</th>
                <th>Target</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((alert) => (
                <tr key={alert.id} onClick={() => focus(alert.targetIp)}>
                  <td>{alert.timestamp}</td>
                  <td><StatusBadge status={alert.severity} /></td>
                  <td>{attackLabel(alert.attackType)}</td>
                  <td>{alert.sourceIp}</td>
                  <td>{alert.targetIp}</td>
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
