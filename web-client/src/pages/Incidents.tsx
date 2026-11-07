import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { EmptyState, Page, StatusBadge } from "../components/ui";
import { attackLabel, clockTime, relativeTime } from "../format";
import { useApp } from "../store";

export function IncidentsPage() {
  const incidents = useApp((state) => state.incidents);
  const assets = useApp((state) => state.assets);
  const setSelectedId = useApp((state) => state.setSelectedId);
  const navigate = useNavigate();
  const [selected, setSelected] = useState<string | null>(null);
  const current = incidents.find((incident) => incident.id === selected) ?? incidents[0] ?? null;
  const timeline = current ? current.alerts.slice().sort((a, b) => (a.timestamp < b.timestamp ? -1 : 1)) : [];

  return (
    <Page title="Incidents" description="Alerts grouped by the server.">
      {incidents.length === 0 ? <EmptyState>No incidents yet.</EmptyState> : (
      <div className="split">
        <div className="panel">
        <table>
          <thead>
            <tr>
              <th>Opened</th>
              <th>Source</th>
              <th>Status</th>
              <th>Alerts</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((incident) => (
              <tr key={incident.id} onClick={() => {
                setSelected(incident.id);
                const host = assets.find((asset) => asset.ip === incident.sourceIp);
                if (host) {
                  setSelectedId(host.id);
                  navigate("/portal");
                }
              }}>
                <td className="mono" title={incident.openedAt}>{relativeTime(incident.openedAt)}</td>
                <td className="mono">{incident.sourceIp}</td>
                <td><StatusBadge status={incident.status} /></td>
                <td>{incident.alerts.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        <section className="panel stack">
          <h3>Timeline</h3>
          {current ? <p className="muted">{current.status}</p> : <p>Select an incident.</p>}
          <ol>
            {timeline.map((alert) => (
              <li key={alert.id}>
                <span className="mono small" title={alert.timestamp}>{clockTime(alert.timestamp)}</span> {attackLabel(alert.attackType)}
              </li>
            ))}
          </ol>
        </section>
      </div>
      )}
    </Page>
  );
}
