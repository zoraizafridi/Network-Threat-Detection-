import { AssetIcon, statusClass } from "./AssetIcon";
import type { FeedAlert } from "../alerts";
import type { Asset, NetLink } from "../types";

export function HostPanel({
  asset,
  links,
  alerts,
  history,
}: {
  asset: Asset | null;
  links: NetLink[];
  alerts: FeedAlert[];
  history: number[];
}) {
  if (!asset) {
    return (
      <section className="panel">
        <h2>Host</h2>
        <p>Select a host on the map or in the list.</p>
      </section>
    );
  }
  const related = links.filter((link) => link.source === asset.id || link.target === asset.id);
  const recent = alerts.filter((alert) => alert.sourceIp === asset.ip || alert.targetIp === asset.ip).slice(-8);
  return (
    <section className="panel stack">
      <h2>
        <AssetIcon type={asset.type} label={asset.type} /> {asset.name}
      </h2>
      <p className="mono">{asset.ip}</p>
      <p>
        {asset.type} · criticality {asset.criticality}
      </p>
      <p className={statusClass(asset.status)}>{asset.status}</p>
      <p>Risk score {asset.riskScore} of 100</p>
      <RiskChart values={history.length ? history : [asset.riskScore]} />
      <h3>Links</h3>
      {related.length === 0 ? <p className="muted">No links.</p> : null}
      <ul>
        {related.map((link) => (
          <li key={link.id} className="mono small">
            {link.id}: {link.source} to {link.target}, {link.status}
          </li>
        ))}
      </ul>
      <h3>Recent alerts</h3>
      {recent.length === 0 ? <p className="muted">No alerts for this host.</p> : null}
      <ul>
        {recent.map((alert) => (
          <li key={alert.id} className="small">
            {alert.severity} {alert.attackType}
          </li>
        ))}
      </ul>
    </section>
  );
}

function RiskChart({ values }: { values: number[] }) {
  const width = 280;
  const height = 80;
  const points = values
    .map((value, index) => {
      const x = values.length === 1 ? width / 2 : (index / (values.length - 1)) * width;
      const y = height - (Math.max(0, Math.min(100, value)) / 100) * height;
      return `${x},${y}`;
    })
    .join(" ");
  return (
    <svg width={width} height={height} role="img" aria-label="Risk history">
      <polyline points={points} fill="none" stroke="#1f3d2b" strokeWidth="1.5" />
    </svg>
  );
}
