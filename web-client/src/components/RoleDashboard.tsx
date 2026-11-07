import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { groupAlerts, type FeedAlert } from "../alerts";
import { attackLabel } from "../format";
import { StatusBadge } from "./ui";
import type { Asset } from "../types";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

interface Profile {
  headline: string;
  kpiLabel: string;
  kpiValue: string;
  chartTitle: string;
  heatTitle: string;
  bottom: string;
  logsTo: string;
}

function profile(role: string, assets: Asset[], alerts: FeedAlert[], alertCount: number): Profile {
  const key = role.toLowerCase();
  const average = assets.length === 0 ? 0 : Math.round(assets.reduce((sum, asset) => sum + asset.riskScore, 0) / assets.length);
  if (key === "admin") {
    return {
      headline: "System Command",
      kpiLabel: "Active users",
      kpiValue: "1",
      chartTitle: "System load",
      heatTitle: "Audit log frequency",
      bottom: "System health check",
      logsTo: "/portal/admin",
    };
  }
  if (key === "analyst") {
    return {
      headline: "Threat Analysis",
      kpiLabel: "Risk score average",
      kpiValue: String(average),
      chartTitle: "Attack vectors",
      heatTitle: "Anomaly density",
      bottom: "Report generation status",
      logsTo: "/portal/reports",
    };
  }
  return {
    headline: "Network Monitor",
    kpiLabel: "Alerts triggered",
    kpiValue: String(alertCount || alerts.length),
    chartTitle: "Traffic volume",
    heatTitle: "Traffic density",
    bottom: "Last login activity",
    logsTo: "/portal/alerts",
  };
}

function greeting(name: string): string {
  const hour = new Date().getHours();
  const part = hour < 12 ? "Good morning" : hour < 17 ? "Good afternoon" : "Good evening";
  const label = name ? name.charAt(0).toUpperCase() + name.slice(1) : "operator";
  return `${part}, ${label}`;
}

function weekCounts(alerts: FeedAlert[]): number[] {
  const counts = [0, 0, 0, 0, 0, 0, 0];
  for (const alert of alerts) {
    const date = new Date(alert.timestamp);
    if (Number.isNaN(date.getTime())) continue;
    const day = date.getDay();
    counts[day === 0 ? 6 : day - 1] += 1;
  }
  return counts;
}

function tone(severity: string): string {
  const value = severity.toUpperCase();
  if (value.includes("CRIT") || value === "HIGH") return "hot";
  if (value.includes("WARN") || value === "MEDIUM" || value.includes("SUSPIC")) return "warn";
  return "ok";
}

function smoothPath(points: { x: number; y: number }[]): string {
  if (points.length === 0) return "";
  let path = `M ${points[0].x} ${points[0].y}`;
  for (let index = 0; index < points.length - 1; index += 1) {
    const p0 = points[index - 1] ?? points[index];
    const p1 = points[index];
    const p2 = points[index + 1];
    const p3 = points[index + 2] ?? p2;
    const c1x = p1.x + (p2.x - p0.x) / 6;
    const c1y = p1.y + (p2.y - p0.y) / 6;
    const c2x = p2.x - (p3.x - p1.x) / 6;
    const c2y = p2.y - (p3.y - p1.y) / 6;
    path += ` C ${c1x} ${c1y}, ${c2x} ${c2y}, ${p2.x} ${p2.y}`;
  }
  return path;
}

function SmoothChart({ values, labels }: { values: number[]; labels?: string[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 520;
  const height = 168;
  const pad = { l: 28, r: 10, t: 14, b: 24 };
  const peak = Math.max(1, ...values);
  const innerW = width - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const points = values.map((value, index) => ({
    x: pad.l + (values.length <= 1 ? innerW / 2 : (index / (values.length - 1)) * innerW),
    y: pad.t + innerH - (value / peak) * innerH,
  }));
  const line = smoothPath(points);
  const base = pad.t + innerH;
  const area = points.length ? `${line} L ${points[points.length - 1].x} ${base} L ${points[0].x} ${base} Z` : "";
  const peakIndex = values.reduce((best, value, index) => (value > values[best] ? index : best), 0);
  return (
    <svg
      className="smooth-chart"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      onPointerLeave={() => setHover(null)}
      onPointerMove={(event) => {
        const rect = event.currentTarget.getBoundingClientRect();
        const x = ((event.clientX - rect.left) / rect.width) * width;
        let nearest = 0;
        points.forEach((point, index) => {
          if (Math.abs(point.x - x) < Math.abs(points[nearest].x - x)) nearest = index;
        });
        setHover(nearest);
      }}
    >
      {[0.33, 0.66, 1].map((step) => {
        const y = pad.t + innerH * (1 - step);
        return <line key={step} className="grid" x1={pad.l} x2={width - pad.r} y1={y} y2={y} />;
      })}
      <line className="base" x1={pad.l} x2={width - pad.r} y1={base} y2={base} />
      <path className="area" d={area} />
      <path className="line" d={line} pathLength={1} />
      {values[peakIndex] > 0 ? <circle className="peak" cx={points[peakIndex].x} cy={points[peakIndex].y} r="3.5" /> : null}
      {hover !== null ? (
        <g>
          <line className="cross" x1={points[hover].x} x2={points[hover].x} y1={pad.t} y2={base} />
          <text className="tip" x={Math.min(width - 70, points[hover].x + 6)} y={pad.t + 12}>{labels?.[hover] ?? ""} {values[hover]}</text>
        </g>
      ) : null}
      {(labels ?? []).map((label, index) => (
        <text key={label} className="axis" x={points[index]?.x ?? 0} y={height - 6} textAnchor="middle">{label}</text>
      ))}
    </svg>
  );
}

function eventName(type: string): string {
  return attackLabel(type);
}

function RhythmChart({ bars, line }: { bars: number[]; line: number[] }) {
  const width = 520;
  const height = 160;
  const peak = Math.max(1, ...bars, ...line);
  const gap = width / bars.length;
  const step = bars.length > 1 ? width / (bars.length - 1) : width;
  const linePoints = line.map((value, index) => {
    const x = index * step;
    const y = height - 16 - (value / peak) * (height - 36);
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg className="dash-rhythm" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Weekly rhythm">
      {bars.map((value, index) => {
        const barHeight = (value / peak) * (height - 36);
        return (
          <rect
            key={DAYS[index]}
            x={index * gap + gap * 0.28}
            y={height - 16 - barHeight}
            width={gap * 0.44}
            height={Math.max(2, barHeight)}
          />
        );
      })}
      <polyline points={linePoints} />
    </svg>
  );
}

function monthWeeks(alerts: FeedAlert[]): number[] {
  const now = new Date();
  const counts = [0, 0, 0, 0, 0];
  for (const alert of alerts) {
    const date = new Date(alert.timestamp);
    if (Number.isNaN(date.getTime())) continue;
    if (date.getMonth() !== now.getMonth() || date.getFullYear() !== now.getFullYear()) continue;
    counts[Math.min(4, Math.floor((date.getDate() - 1) / 7))] += 1;
  }
  return counts;
}

function vectorCounts(alerts: FeedAlert[]): { label: string; value: number }[] {
  const counts = new Map<string, number>();
  alerts.forEach((alert) => {
    const key = alert.attackType || alert.severity || "Alert";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  });
  return [...counts.entries()].map(([label, value]) => ({ label, value }));
}

function heatCells(alerts: FeedAlert[]): number[] {
  const cells = Array.from({ length: 7 * 12 }, () => 0);
  alerts.forEach((alert, index) => {
    let hash = index + 1;
    for (const char of alert.id) hash = (hash * 33 + char.charCodeAt(0)) >>> 0;
    cells[hash % cells.length] += 1;
  });
  return cells;
}

function heatColor(value: number, peak: number): string {
  if (value <= 0 || peak <= 0) return "#1A2E22";
  const ratio = value / peak;
  if (ratio > 0.75) return "#D9A05B";
  if (ratio > 0.45) return "#8C6A3A";
  if (ratio > 0.2) return "#3D4A32";
  return "#243528";
}

function Rings({ values }: { values: { label: string; value: number }[] }) {
  return (
    <div className="dash-rings">
      {values.map((item) => {
        const radius = 28;
        const circ = 2 * Math.PI * radius;
        const dash = (Math.max(0, Math.min(100, item.value)) / 100) * circ;
        return (
          <div key={item.label} className="dash-ring">
            <svg viewBox="0 0 72 72" aria-hidden="true">
              <circle cx="36" cy="36" r={radius} />
              <circle cx="36" cy="36" r={radius} strokeDasharray={`${dash} ${circ}`} />
            </svg>
            <div>
              <p>{item.value}%</p>
              <span>{item.label}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function gauge(id: string, salt: number): number {
  let hash = salt;
  for (const char of id) hash = (hash * 33 + char.charCodeAt(0)) >>> 0;
  return 18 + (hash % 62);
}

export function RoleDashboard({
  role,
  username,
  assets,
  alerts,
  alertCount,
  disconnected,
  running,
  incidentCount,
}: {
  role: string;
  username: string;
  assets: Asset[];
  alerts: FeedAlert[];
  alertCount: number;
  disconnected: boolean;
  running: boolean;
  incidentCount: number;
}) {
  const [range, setRange] = useState<"week" | "month">("week");
  const copy = profile(role, assets, alerts, alertCount);
  const week = useMemo(() => weekCounts(alerts), [alerts]);
  const month = useMemo(() => monthWeeks(alerts), [alerts]);
  const shown = range === "week" ? week : month;
  const labels = range === "week" ? DAYS : ["W1", "W2", "W3", "W4", "W5"];
  const vectors = useMemo(() => vectorCounts(alerts), [alerts]);
  const events = groupAlerts([...alerts].reverse()).slice(0, 8);
  const now = Date.now();
  const recent = alerts.filter((alert) => now - new Date(alert.timestamp).getTime() < 86_400_000).length;
  const earlier = alerts.length - recent;
  const admin = role.toLowerCase() === "admin";
  const analyst = role.toLowerCase() === "analyst";
  const emptyCopy = disconnected ? "No data yet. Stream disconnected, retrying." : "No data yet.";
  const checked = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  const series = analyst ? vectors.map((item) => item.value) : shown;
  const seriesLabels = analyst ? vectors.map((item) => item.label) : labels;
  const hasSeries = series.some((value) => value > 0);
  const dayPeak = Math.max(1, ...week);

  return (
    <div className="dash">
      <div className="dash-top">
        <section className="dash-card dash-timeline">
          <header className="card-head">
            <span className="card-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg></span>
            <span className="card-titles"><h2>Recent system events</h2><p>Same feed as active alerts</p></span>
          </header>
          {events.length === 0 ? (
            <p className="dash-empty">{emptyCopy}</p>
          ) : (
            <div className="event-scroll">
              <table className="event-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Event</th>
                    <th>Source</th>
                    <th>Target</th>
                    <th>Time</th>
                    <th>Tag</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((group) => {
                    const alert = group.latest;
                    const when = new Date(alert.timestamp);
                    const clock = Number.isNaN(when.getTime()) ? alert.timestamp : when.toLocaleTimeString();
                    const simulation = alert.id.startsWith("sim-") || alert.detectorName === "Field station";
                    return (
                      <tr key={alert.id}>
                        <td><StatusBadge status={alert.severity} /></td>
                        <td>{eventName(alert.attackType || alert.severity)}{group.count > 1 ? <i className="count-chip">x{group.count}</i> : null}</td>
                        <td className="mono">{alert.sourceIp}</td>
                        <td className="mono">{alert.targetIp}</td>
                        <td className="mono">{clock}</td>
                        <td>{simulation ? <span className="sim-pill">SIMULATION</span> : null}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {alerts.length > 8 ? <Link className="view-all" to="/portal/alerts">View all</Link> : null}
            </div>
          )}
        </section>
        <section className="dash-card dash-kpi">
          <header className="card-head">
            <span className="card-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M5 19V9M12 19V5M19 19v-6" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg></span>
            <span className="card-titles"><h2>{copy.kpiLabel}</h2></span>
            {earlier > 0 ? <span className="delta-chip">{recent} today</span> : null}
          </header>
          <p className="stat-value">{copy.kpiValue}</p>
          {week.some((value) => value > 0) ? <SmoothChart values={week} labels={DAYS} /> : <p className="dash-empty">{emptyCopy}</p>}
        </section>
      </div>

      <div className="dash-mid">
        <section className="dash-card dash-chart">
          <div className="card-head">
            <span className="card-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 16l5-5 4 3 7-7" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg></span>
            <span className="card-titles"><h2>{admin ? "System load" : copy.chartTitle}</h2></span>
            {admin ? null : (
              <div className="dash-filters">
                <button type="button" className={range === "week" ? "on" : undefined} onClick={() => setRange("week")}>This week</button>
                <button type="button" className={range === "month" ? "on" : undefined} onClick={() => setRange("month")}>This month</button>
              </div>
            )}
          </div>
          {!(analyst && hasSeries) ? (
            <p className="dash-empty">{admin ? "No host load history is reported to this client." : analyst ? emptyCopy : "No traffic counters in this feed."}</p>
          ) : (
            <>
              <SmoothChart values={series} labels={seriesLabels} />
              <div className="dash-days">{seriesLabels.map((day) => <span key={day}>{day}</span>)}</div>
            </>
          )}
        </section>
        <section className="dash-card dash-heat audit-card">
          <div className="card-head">
            <span className="card-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 18h4V8H4v10Zm6 0h4V4h-4v14Zm6 0h4v-7h-4v7Z" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg></span>
            <span className="card-titles"><h2>{copy.heatTitle}</h2><p>Session counts</p></span>
            <p className="dash-legend"><span>Low</span><span>High</span></p>
          </div>
          {admin || week.every((value) => value === 0) ? (
            <p className="dash-empty">{admin ? "No audit records in this session." : emptyCopy}</p>
          ) : (
            <div className="dash-heat-days dash-heat-bars">
              {DAYS.map((day, index) => (
                <span key={day} title={`${day}: ${week[index]}`}>
                  {day}
                  <i style={{ height: `${Math.max(4, (week[index] / dayPeak) * 48)}px`, opacity: week[index] === 0 ? 0.25 : 0.35 + (week[index] / dayPeak) * 0.65 }} />
                </span>
              ))}
            </div>
          )}
        </section>
        <section className="dash-card dash-health">
          <header className="card-head">
            <span className="card-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 12h4l2-5 4 10 2-5h4" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg></span>
            <span className="card-titles"><h2>System health</h2><p>Last check on each row</p></span>
          </header>
          <ul className="health-list">
            <li><i className={disconnected ? "stream-dot is-down" : "stream-dot"} /><strong>Data stream</strong><span>{disconnected ? "Disconnected, retrying." : alerts.length === 0 ? "Connected, no events yet." : "Connected."}</span><time className="mono">{checked}</time></li>
            <li><i className="stream-dot is-idle" /><strong>Database</strong><span>Not reported by this client.</span><time className="mono">{checked}</time></li>
            <li><i className={username ? "stream-dot" : "stream-dot is-down"} /><strong>Auth</strong><span>{username ? `Signed in as ${username}.` : "Signed out."}</span><time className="mono">{checked}</time></li>
            <li><i className={assets.length ? "stream-dot" : "stream-dot is-idle"} /><strong>Node agents</strong><span>{assets.length ? `${assets.length} assets in the latest snapshot.` : "No assets in the snapshot."}</span><time className="mono">{checked}</time></li>
            <li><i className={disconnected ? "stream-dot is-down" : "stream-dot"} /><strong>Alerting</strong><span>{disconnected ? "Stale until the stream returns." : alerts.length === 0 ? "Connected, no events yet." : "Feed connected."}</span><time className="mono">{checked}</time></li>
          </ul>
        </section>
      </div>

    </div>
  );
}
