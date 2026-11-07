import { Link, useParams } from "react-router-dom";
import { AssetIcon } from "../components/AssetIcon";
import { HostPanel } from "../components/HostPanel";
import { Page, StatusBadge } from "../components/ui";
import { useApp } from "../store";

export function HostsPage() {
  const assets = useApp((state) => state.assets);
  return (
    <Page title="Hosts" description="Assets in the latest network snapshot.">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>IP</th>
            <th>Type</th>
            <th>Criticality</th>
            <th>Risk</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => (
            <tr key={asset.id}>
              <td>
                <Link to={`/portal/hosts/${asset.id}`} onClick={() => useApp.getState().setSelectedId(asset.id)}>{asset.name}</Link>
              </td>
              <td className="mono">{asset.ip}</td>
              <td>
                <AssetIcon type={asset.type} label={asset.type} /> {asset.type}
              </td>
              <td>{asset.criticality}</td>
              <td>{asset.riskScore}</td>
              <td><StatusBadge status={asset.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </Page>
  );
}

export function HostDetail() {
  const { id } = useParams();
  const assets = useApp((state) => state.assets);
  const links = useApp((state) => state.links);
  const alerts = useApp((state) => state.alerts);
  const history = useApp((state) => state.riskHistory);
  const asset = assets.find((item) => item.id === id) ?? null;
  return (
    <div className="stack">
      <p>
        <Link to="/portal/hosts">All hosts</Link>
      </p>
      <HostPanel asset={asset} links={links} alerts={alerts} history={asset ? (history[asset.id] ?? []) : []} />
      <p className="muted">Assigned tasks and mitigation actions are listed by team on the <Link to="/portal/planner">planner</Link>.</p>
    </div>
  );
}
