import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { readJson } from "../api";
import { EmptyState, Page, Panel, StatusBadge } from "../components/ui";
import { relativeTime } from "../format";
import { useApp } from "../store";
import type { IncidentRow } from "../types";

export function ReportsPage() {
  const incidents = useApp((state) => state.incidents);
  const assets = useApp((state) => state.assets);
  const report = useApp((state) => state.report);
  const setReport = useApp((state) => state.setReport);
  const setSelectedId = useApp((state) => state.setSelectedId);
  const navigate = useNavigate();
  const [failed, setFailed] = useState(false);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [sortKey, setSortKey] = useState<"opened" | "alerts" | "host">("opened");
  const [page, setPage] = useState(0);
  const [raw, setRaw] = useState(false);
  const [open, setOpen] = useState<IncidentRow | null>(null);
  const [menu, setMenu] = useState(false);

  function load() {
    setFailed(false);
    readJson<{ text: string }>("/api/report")
      .then((body) => setReport(body.text))
      .catch(() => setFailed(true));
  }

  useEffect(() => {
    load();
  }, [setReport]);

  const hostFor = (ip: string) => assets.find((asset) => asset.ip === ip);
  const severityOf = (row: IncidentRow) => row.alerts[0]?.severity ?? "";
  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = incidents.filter((row) => {
      const host = hostFor(row.sourceIp);
      if (severity && severityOf(row) !== severity) return false;
      if (status && row.status !== status) return false;
      if (!needle) return true;
      return (host?.name ?? "").toLowerCase().includes(needle) || row.sourceIp.includes(needle);
    });
    filtered.sort((a, b) => {
      if (sortKey === "alerts") return b.alerts.length - a.alerts.length;
      if (sortKey === "host") return (hostFor(a.sourceIp)?.name ?? a.sourceIp).localeCompare(hostFor(b.sourceIp)?.name ?? b.sourceIp);
      return new Date(b.openedAt).getTime() - new Date(a.openedAt).getTime();
    });
    return filtered;
  }, [incidents, query, severity, status, sortKey, assets]);
  const slice = rows.slice(page * 20, page * 20 + 20);
  const openCount = incidents.filter((row) => row.status === "OPEN").length;
  const highest = incidents.reduce((best, row) => {
    const rank = severityOf(row).includes("CRIT") ? 3 : severityOf(row) === "HIGH" ? 2 : severityOf(row) ? 1 : 0;
    return rank > best.rank ? { rank, label: severityOf(row) } : best;
  }, { rank: 0, label: "" });
  const hosts = new Set(incidents.map((row) => row.sourceIp)).size;
  const times = incidents.map((row) => row.openedAt).filter(Boolean);
  const oneStamp = times.length > 0 && times.every((time) => time === times[0]);
  const counts = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => ({
    level,
    count: incidents.filter((row) => severityOf(row) === level).length,
  }));
  const peak = Math.max(1, ...counts.map((row) => row.count));

  function download(name: string, text: string, type: string) {
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Page title="Reports" description="Incidents from the same feed as the Incidents page, plus the server text.">
      <div className="row no-print">
        <button type="button" className="primary" onClick={() => setMenu((value) => !value)} disabled={!report && incidents.length === 0}>Export</button>
        {menu ? (
          <div className="menu-pop">
            <button type="button" onClick={() => download("incident-report.txt", report, "text/plain")}>Text (.txt)</button>
            <button type="button" onClick={() => download("incidents.csv", ["severity,host,ip,status,alerts,opened", ...rows.map((row) => {
              const host = hostFor(row.sourceIp);
              return [severityOf(row), host?.name ?? "", row.sourceIp, row.status, row.alerts.length, row.openedAt].join(",");
            })].join("\n"), "text/csv")}>CSV</button>
            <button type="button" onClick={() => window.print()}>Print / PDF</button>
          </div>
        ) : null}
      </div>
      <div className="stat-row">
        <article className="stat-tile"><strong className="stat-value">{incidents.length}</strong><span>Total incidents</span></article>
        <article className="stat-tile"><strong className="stat-value">{openCount}</strong><span>Open</span></article>
        <article className="stat-tile"><strong>{highest.label ? <StatusBadge status={highest.label} /> : "—"}</strong><span>Highest severity</span></article>
        <article className="stat-tile"><strong className="stat-value">{hosts}</strong><span>Hosts affected</span></article>
      </div>
      <div className="plan-grid report-section">
        <Panel className="span-6" title="Incidents by severity">
          {incidents.length === 0 ? <EmptyState>No incidents yet.</EmptyState> : counts.map((row) => (
            <p key={row.level}><StatusBadge status={row.level} /> <span className="risk-bar"><i style={{ width: `${(row.count / peak) * 100}%`, background: "var(--info)" }} /></span> {row.count}</p>
          ))}
        </Panel>
        <Panel className="span-6" title="Incidents over time">
          {incidents.length === 0 ? <EmptyState>No incidents yet.</EmptyState> : oneStamp ? <p className="muted">All incidents share one timestamp.</p> : <p className="muted">{times.length} incidents across distinct times.</p>}
        </Panel>
        <Panel className="span-12" title="Incidents">
          {failed ? <p>The report could not be loaded. <button type="button" onClick={load}>Retry</button></p> : null}
          <div className="row no-print">
            <input value={query} placeholder="Search host" aria-label="Search host" onChange={(event) => { setQuery(event.target.value); setPage(0); }} />
            <select value={severity} aria-label="Severity" onChange={(event) => setSeverity(event.target.value)}>
              <option value="">Any severity</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
            </select>
            <select value={status} aria-label="Status" onChange={(event) => setStatus(event.target.value)}>
              <option value="">Any status</option>
              <option value="OPEN">Open</option>
              <option value="CLOSED">Closed</option>
            </select>
          </div>
          {rows.length === 0 ? <EmptyState>No incidents match.</EmptyState> : (
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th><button type="button" onClick={() => setSortKey("host")}>Host</button></th>
                  <th>Status</th>
                  <th><button type="button" onClick={() => setSortKey("alerts")}>Alerts</button></th>
                  <th><button type="button" onClick={() => setSortKey("opened")}>Opened</button></th>
                </tr>
              </thead>
              <tbody>
                {slice.map((row) => {
                  const host = hostFor(row.sourceIp);
                  return (
                    <tr key={row.id} onClick={() => setOpen(row)}>
                      <td>{severityOf(row) ? <StatusBadge status={severityOf(row)} /> : "—"}</td>
                      <td>{host?.name ?? "—"}<br /><span className="mono muted">{row.sourceIp}</span></td>
                      <td><StatusBadge status={row.status} /></td>
                      <td className="mono">{row.alerts.length}</td>
                      <td className="mono" title={row.openedAt}>{row.openedAt ? relativeTime(row.openedAt) : "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <div className="row">
            <button type="button" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous</button>
            <button type="button" disabled={(page + 1) * 20 >= rows.length} onClick={() => setPage((value) => value + 1)}>Next</button>
          </div>
          {open ? (
            <Panel title={hostFor(open.sourceIp)?.name ?? "Incident"} subtitle={`${open.alerts.length} alerts`}>
              <p><StatusBadge status={open.status} /></p>
              <p className="mono" title={open.id}>{open.openedAt || "—"}</p>
              <button type="button" className="secondary" onClick={() => { const host = hostFor(open.sourceIp); if (host) { setSelectedId(host.id); navigate("/portal"); } }}>Show on map</button>
            </Panel>
          ) : null}
        </Panel>
        <Panel className="span-12" title="Raw report" action={<button type="button" className="secondary" onClick={() => setRaw((value) => !value)}>{raw ? "Hide server text" : "Show server text"}</button>}>
          {raw ? (
            <>
              <button type="button" onClick={() => navigator.clipboard.writeText(report)}>Copy</button>
              <pre className="report">{report || "—"}</pre>
            </>
          ) : <p className="muted">The server text stays collapsed.</p>}
        </Panel>
      </div>
    </Page>
  );
}
