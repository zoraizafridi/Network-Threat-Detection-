import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { HttpStatusError, loadIncidentDetail, type IncidentDetail, type TimelineEntry } from "../api";
import { EmptyState, Page, Panel, StatusBadge } from "../components/ui";
import { attackLabel, clockTime, relativeTime } from "../format";
import { useApp } from "../store";

const DETAIL_POLL_MS = 5000;

export function IncidentsPage() {
  const incidents = useApp((state) => state.incidents);
  const assets = useApp((state) => state.assets);
  const setSelectedId = useApp((state) => state.setSelectedId);
  const navigate = useNavigate();
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [failed, setFailed] = useState("");
  const [tick, setTick] = useState(0);

  const current = incidents.find((incident) => incident.id === selected) ?? incidents[0] ?? null;
  const currentId = current?.id ?? null;

  useEffect(() => {
    if (!currentId) {
      setDetail(null);
      return undefined;
    }
    let stop = false;
    async function pull() {
      try {
        const body = await loadIncidentDetail(currentId as string);
        if (!stop) {
          setDetail(body);
          setFailed("");
        }
      } catch (error) {
        if (!stop) {
          setFailed(
            error instanceof HttpStatusError && error.status === 404
              ? "That incident is no longer on the server."
              : "The incident timeline could not be loaded.",
          );
        }
      }
    }
    void pull();
    const timer = window.setInterval(() => setTick((value) => value + 1), DETAIL_POLL_MS);
    return () => {
      stop = true;
      window.clearInterval(timer);
    };
  }, [currentId, tick]);

  const timeline = detail?.id === currentId ? detail.timeline : [];

  function focusHost() {
    if (!current) return;
    const host = assets.find((asset) => asset.ip === current.sourceIp);
    if (!host) {
      setFailed(`No host with address ${current.sourceIp} is on the map.`);
      return;
    }
    setSelectedId(host.id);
    navigate("/portal");
  }

  return (
    <Page title="Incidents" description="Alerts grouped per source by the server, with the timeline that produced them.">
      {incidents.length === 0 ? (
        <EmptyState>No incidents yet. They open once a source trips more than one detector.</EmptyState>
      ) : (
        <div className="board-12">
          <Panel className="span-7" title="Open incidents" subtitle="Newest activity first, click a row to read it">
            <div className="table-scroll">
              <table className="incident-table">
                <thead>
                  <tr>
                    <th>Opened</th>
                    <th>Source</th>
                    <th>Status</th>
                    <th>Alerts</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((incident) => (
                    <tr
                      key={incident.id}
                      onClick={() => setSelected(incident.id)}
                      data-selected={incident.id === currentId}
                    >
                      <td className="mono" title={incident.openedAt}>{relativeTime(incident.openedAt)}</td>
                      <td className="mono">{incident.sourceIp}</td>
                      <td><StatusBadge status={incident.status} /></td>
                      <td className="mono">{incident.alerts.length}</td>
                      <td className="mono">
                        {incident.alerts.length > 0
                          ? relativeTime(incident.alerts[incident.alerts.length - 1].timestamp)
                          : "unknown"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel className="span-5" title="Timeline" subtitle={current ? current.sourceIp : "Select an incident"}>
            {!current ? (
              <EmptyState>Select a row to read its timeline.</EmptyState>
            ) : (
              <>
                <div className="row">
                  <StatusBadge status={detail?.status ?? current.status} />
                  {detail?.highestSeverity ? <StatusBadge status={detail.highestSeverity} /> : null}
                  <button type="button" className="secondary" onClick={focusHost}>Focus host</button>
                </div>
                {failed ? <p className="notice">{failed}</p> : null}
                <table>
                  <tbody>
                    <tr><td>Alerts</td><td className="mono">{detail?.alertCount ?? current.alerts.length}</td></tr>
                    <tr>
                      <td>First seen</td>
                      <td className="mono">{detail?.firstSeen ? clockTime(detail.firstSeen) : "unknown"}</td>
                    </tr>
                    <tr>
                      <td>Last seen</td>
                      <td className="mono">{detail?.lastSeen ? relativeTime(detail.lastSeen) : "unknown"}</td>
                    </tr>
                    <tr><td>Detectors</td><td>{detail?.detectors.length ? detail.detectors.join(", ") : "unknown"}</td></tr>
                    <tr>
                      <td>Types</td>
                      <td>{detail?.attackTypes.length ? detail.attackTypes.map(attackLabel).join(", ") : "unknown"}</td>
                    </tr>
                  </tbody>
                </table>
                {timeline.length === 0 ? (
                  <EmptyState>No timeline entries yet. The first alert arrives with the next poll.</EmptyState>
                ) : (
                  <ol className="timeline">
                    {timeline.map((entry, index) => (
                      <TimelineRow key={`${entry.kind}-${entry.alertId ?? index}`} entry={entry} />
                    ))}
                  </ol>
                )}
              </>
            )}
          </Panel>
        </div>
      )}
    </Page>
  );
}

function TimelineRow({ entry }: { entry: TimelineEntry }) {
  return (
    <li data-kind={entry.kind}>
      <span className="mono small" title={entry.at ?? undefined}>
        {entry.at ? clockTime(entry.at) : "--:--:--"}
      </span>{" "}
      {entry.severity ? <StatusBadge status={entry.severity} /> : null}{" "}
      <strong>{entry.title}</strong>
      {entry.occurrences > 1 ? <span className="mono small"> x{entry.occurrences}</span> : null}
      <p className="muted small">{entry.detail}</p>
    </li>
  );
}
