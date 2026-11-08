import { useEffect, useState } from "react";
import { resetAttackState } from "../attackPhase";
import { HttpStatusError, request, runScenario } from "../api";
import { launchReady } from "../launch";
import { attackLabel } from "../format";
import { EmptyState, MapPanel, Page, Panel, StatusBadge } from "../components/ui";
import { NetworkMap } from "../components/NetworkMap";
import { accessDenied, canLaunchAttack } from "../permissions";
import { useApp } from "../store";

const TYPES = [
  { id: "PORT_SCAN", label: "Port scan" },
  { id: "BRUTE_FORCE", label: "Brute force" },
  { id: "DOS_FLOOD", label: "DoS flood" },
  { id: "DATA_TRANSFER", label: "Data transfer" },
];

const PRESETS = [
  { id: "beaconing", label: "Beaconing" },
  { id: "lateral-movement", label: "Lateral movement" },
  { id: "intel-contact", label: "Indicator contact" },
];

export function AttackLab() {
  const role = useApp((state) => state.user?.role ?? "");
  const assets = useApp((state) => state.assets);
  const alerts = useApp((state) => state.alerts);
  const selectedId = useApp((state) => state.selectedId);
  const setSelectedId = useApp((state) => state.setSelectedId);
  const setNotice = useApp((state) => state.setNotice);
  const [type, setType] = useState(TYPES[0].id);
  const [preset, setPreset] = useState(PRESETS[0].id);
  const [message, setMessage] = useState("");
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");

  useEffect(() => () => resetAttackState(), []);

  if (!canLaunchAttack(role)) {
    return <p>{accessDenied(role)}</p>;
  }

  async function launch(kind: string, source: string, target: string) {
    setNotice("");
    try {
      await request("/api/attacks", {
        method: "POST",
        body: JSON.stringify({ type: kind, src: source, dst: target }),
      });
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 403) setNotice(accessDenied(role));
      if (error instanceof HttpStatusError && error.status === 400) setNotice("Unknown host or attack type.");
    }
  }

  async function multiStage() {
    const sequence = ["PORT_SCAN", "BRUTE_FORCE", "DOS_FLOOD"];
    for (const kind of sequence) {
      await launch(kind, src, dst);
    }
  }

  async function runPreset() {
    setNotice("");
    setMessage("");
    const source = assets.find((asset) => asset.id === src)?.ip;
    const target = assets.find((asset) => asset.id === dst)?.ip;
    try {
      const result = await runScenario(preset, source, target);
      setMessage(
        `${result.title}: ${result.events} events submitted from ${result.source} to ${result.target}.`,
      );
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 403) setMessage(accessDenied(role));
      else if (error instanceof HttpStatusError && error.status === 400) setMessage("That preset is not known.");
      else setMessage("The preset could not be run.");
    }
  }

  const recent = alerts.slice(-6);

  return (
    <Page title="Attack lab" description="Launched attacks are simulated and tagged when they appear in the feed.">
      <div className="row">
        <label>
          Type{" "}
          <select value={type} onChange={(event) => setType(event.target.value)}>
            {TYPES.map((item) => (
              <option key={item.id} value={item.id}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Source{" "}
          <select value={src} onChange={(event) => setSrc(event.target.value)}>
            <option value="">Choose host</option>
            {assets.map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Target{" "}
          <select value={dst} onChange={(event) => setDst(event.target.value)}>
            <option value="">Choose host</option>
            {assets.map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.name}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="secondary" onClick={() => selectedId && setSrc(selectedId)}>
          Use selection as source
        </button>
        <button type="button" className="secondary" onClick={() => selectedId && setDst(selectedId)}>
          Use selection as target
        </button>
        <button
          type="button"
          className="primary"
          disabled={!launchReady(src, dst)}
          onClick={() => {
            void launch(type, src, dst);
          }}
        >
          Launch
        </button>
        <button type="button" className="secondary" disabled={!launchReady(src, dst)} onClick={multiStage}>
          Multi-stage attack
        </button>
      </div>
      <div className="row">
        <label>
          Preset{" "}
          <select value={preset} onChange={(event) => setPreset(event.target.value)}>
            {PRESETS.map((item) => (
              <option key={item.id} value={item.id}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="secondary" disabled={!launchReady(src, dst)} onClick={runPreset}>
          Run preset
        </button>
        <span className="small">
          A preset is a named shape rather than one burst: beacons repeat, lateral movement crosses hosts, and
          the indicator contact reaches a listed address, domain and digest.
        </span>
      </div>
      {message ? <p className="notice">{message}</p> : null}
      <div className="board-12">
        <MapPanel className="span-8" title="Network topology" subtitle="Same scene as Overview">
          <NetworkMap assets={assets} selectedId={selectedId} onSelect={(id) => setSelectedId(id || null)} />
        </MapPanel>
        <Panel className="span-4" title="Alerts from this session" subtitle="Launches from this page">
          {recent.length === 0 ? <EmptyState>Launch an attack to watch the detectors.</EmptyState> : null}
          <ul>
            {recent.map((alert) => (
              <li key={alert.id}>
                <StatusBadge status={alert.severity} /> {attackLabel(alert.attackType)} <span className="mono">{alert.sourceIp}</span> to <span className="mono">{alert.targetIp}</span> <span className="sim-pill">SIMULATION</span>
              </li>
            ))}
          </ul>
          <p className="small">Risk on the map updates when the server sends a network snapshot.</p>
        </Panel>
      </div>
    </Page>
  );
}
