import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { gsap } from "gsap";
import { loadAlertQuality, type AlertQualityBody } from "../api";
import { NetworkStage } from "../components/NetworkMap";
import { RoleDashboard } from "../components/RoleDashboard";
import { canLaunchAttack } from "../permissions";
import { getScenario, scenarioPause, scenarioReplay, scenarioResume, scenarioSpeed, scenarioStep, STAGE_NAMES, subscribeScenario } from "../scenario";
import { attackLabel, clockTime } from "../format";
import { EmptyState, MapPanel, Panel, sentence, StatusBadge } from "../components/ui";
import { useApp } from "../store";
import type { Asset } from "../types";
import { useReducedMotion } from "../useReducedMotion";
import { Link } from "react-router-dom";

export const portalAttack = {
  current: null as null | ((sourceNode: Asset, targetNode: Asset) => void),
};

export function Overview() {
  const assets = useApp((state) => state.assets);
  const alerts = useApp((state) => state.alerts);
  const selectedHost = useApp((state) => state.selectedId);
  const setSelectedId = useApp((state) => state.setSelectedId);
  const reduced = useReducedMotion();
  const scenario = useSyncExternalStore(subscribeScenario, getScenario);
  const live = scenario.phase === "run" || (scenario.phase === "paused" && scenario.stage >= 0 && scenario.stage <= 3);
  const flight = live && scenario.segmentFrom && scenario.segmentTo
    ? {
        token: `${scenario.token}-${scenario.stage}-${scenario.hop}`,
        sourceId: scenario.segmentFrom,
        targetId: scenario.segmentTo,
        pathIds: scenario.path,
        durationMs: scenario.segmentMs,
      }
    : null;
  const listRef = useRef<HTMLDivElement>(null);
  const running = useApp((state) => state.running);
  const disconnected = useApp((state) => state.disconnected);
  const links = useApp((state) => state.links);
  const incidentCount = useApp((state) => state.incidents.filter((row) => row.status === "OPEN").length);
  const quality = useQuality();

  const host = assets.find((asset) => asset.id === selectedHost) ?? null;
  const shown = alerts.slice().reverse().slice(0, 12);
  const freshId = shown[0]?.id ?? null;
  const marked = host ? scenario.marks[host.id] : undefined;
  const riskText = marked === "COMPROMISED" ? 95 : (host?.riskScore ?? 0);

  useEffect(() => {
    const row = listRef.current?.querySelector<HTMLElement>("[data-fresh='true']");
    if (!row) return;
    if (reduced) {
      gsap.set(row, { x: 0, autoAlpha: 1 });
      return;
    }
    const tween = gsap.fromTo(
      row,
      { x: -24, autoAlpha: 0 },
      { x: 0, autoAlpha: 1, duration: 0.45, ease: "power3.out" },
    );
    return () => { tween.kill(); };
  }, [freshId, reduced]);

  function choose(id: string) {
    setSelectedId(id || null);
  }

  const role = useApp((state) => state.user?.role ?? "");
  const username = useApp((state) => state.user?.username ?? "operator");
  const alertCount = useApp((state) => state.alertCount);

  const stageIndex = scenario.stage;
  const compromisedCount = assets.filter((asset) => (scenario.marks[asset.id] ?? asset.status) === "COMPROMISED").length;
  const latest = alerts[alerts.length - 1];
  const latestLabel = latest ? relativeTime(latest.timestamp) : "None";
  const nodeCount = useCount(assets.length);
  const openCount = useCount(incidentCount);
  const hitCount = useCount(compromisedCount);
  const grouped = shown.map((row) => ({
    ...row,
    count: row.occurrences ?? 1,
    simulation: row.simulated ?? row.id.startsWith("sim-"),
  }));
  const neighbours = host
    ? links
        .filter((link) => link.source === host.id || link.target === host.id)
        .map((link) => assets.find((asset) => asset.id === (link.source === host.id ? link.target : link.source)))
        .filter((asset): asset is Asset => Boolean(asset))
    : [];
  const counts = assets.reduce<Record<string, number>>((map, asset) => {
    const type = asset.type;
    map[type] = (map[type] ?? 0) + 1;
    const status = scenario.marks[asset.id] ?? asset.status;
    map[`status:${status}`] = (map[`status:${status}`] ?? 0) + 1;
    return map;
  }, {});

  return (
    <div className="station-board">
      <header className="status-strip">
        <p className="greet">{greeting(username)}</p>
        <div className="stat-row">
          <article className="stat-tile">
            <span className="card-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M12 3v3M12 18v3M3 12h3M18 12h3" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg></span>
            <strong className="stat-value">{nodeCount}</strong>
            <span>Active nodes</span>
          </article>
          <article className="stat-tile">
            <span className="card-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 4 3 19h18L12 4Z" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg></span>
            <strong className="stat-value">{openCount}{incidentCount > 0 ? <i className="stream-dot is-down" /> : null}</strong>
            <span>Open incidents</span>
          </article>
          <article className="stat-tile">
            <span className="card-ico" aria-hidden="true"><i className={compromisedCount > 0 ? "stream-dot is-down" : "stream-dot"} /></span>
            <strong className="stat-value">{hitCount}</strong>
            <span>Compromised nodes</span>
          </article>
          <article className="stat-tile">
            <span className="card-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M12 8v5l3 2" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg></span>
            <strong className="stat-state">{latestLabel}</strong>
            <span>Last event</span>
          </article>
        </div>
      </header>
      <section className="quality-strip" aria-label="Alert quality">
        <span><b>{quality?.raw ?? 0}</b> detected</span>
        <span><b>{quality?.delivered ?? 0}</b> reached the feed</span>
        <span><b>{quality ? Math.round(quality.ratio * 100) : 0}%</b> delivery ratio</span>
        <span><b>{quality?.folded ?? 0}</b> folded repeats</span>
        <span><b>{quality?.suppressed ?? 0}</b> suppressed</span>
        <Link to="/portal/alerts">Triage alerts</Link>
      </section>
      <div className="ops-board" id="live-map">
        <section className="panel toolbar-card">
        <div className="ops-toolbar">
          <ol className="stage-steps" aria-label="Attack stage">
            {stageIndex < 0 ? <li className="idle-label">Idle</li> : null}
            {STAGE_NAMES.map((label, index) => (
              <li key={label} className={stageIndex > index ? "is-done" : stageIndex === index ? "is-now" : undefined}>
                <span>{stageIndex > index ? "✓" : index + 1}</span>
                {label}
              </li>
            ))}
          </ol>
          <div className="play-set">
          <button type="button" className={scenario.phase === "idle" ? "primary" : undefined} onClick={() => (scenario.phase === "paused" ? scenarioResume() : scenario.phase === "run" || scenario.phase === "hold" ? scenarioPause() : scenarioReplay())} disabled={scenario.phase === "idle" && !scenario.attackerId}>{scenario.phase === "run" || scenario.phase === "hold" ? "Pause" : "Play"}</button>
          <button type="button" onClick={() => scenarioPause()} disabled={scenario.phase !== "run" && scenario.phase !== "hold"}>Pause</button>
          <button type="button" onClick={() => scenarioStep()} disabled={scenario.phase === "idle"}>Step</button>
          <button type="button" onClick={() => scenarioReplay()} disabled={!scenario.attackerId}>Replay</button>
          </div>
          <div className="speed-set" role="group" aria-label="Speed">
            {([1, 2, 4] as const).map((value) => (
              <button key={value} type="button" className={scenario.speed === value ? "on" : undefined} onClick={() => scenarioSpeed(value)}>{value}x</button>
            ))}
          </div>
        </div>
        </section>
        <MapPanel className="span-8" title="Network topology" subtitle="Same scene on every page">
          <NetworkStage
            assets={assets}
            selectedId={selectedHost}
            onSelect={choose}
            attack={flight}
            phase={live ? "traveling" : "idle"}
            traffic={running && !disconnected && scenario.phase === "idle"}
            paused={scenario.phase === "paused"}
            marks={scenario.marks}
            frameKey={scenario.frameKey}
            frameIds={live ? scenario.path : []}
          />
        </MapPanel>
        <div className="ops-side span-4">
          <Panel title="Active alerts">
            {grouped.length === 0 ? (
              <EmptyState>{disconnected ? "No active alerts. Stream disconnected, retrying." : "No active alerts."}</EmptyState>
            ) : (
              <div className="ops-scroll" ref={listRef}>
                {grouped.map((row) => {
                  const device = assets.find((asset) => asset.ip === row.targetIp) ?? assets.find((asset) => asset.ip === row.sourceIp);
                  const source = assets.find((asset) => asset.ip === row.sourceIp);
                  const target = assets.find((asset) => asset.ip === row.targetIp);
                  const clock = clockTime(row.timestamp);
                  return (
                    <button key={row.id} type="button" className="alert-row" data-fresh={row.id === freshId ? "true" : "false"} onClick={() => device && choose(device.id)} title={row.timestamp}>
                      <StatusBadge status={row.severity} />
                      <span className="alert-title">{attackLabel(row.attackType)}{row.count > 1 ? <i className="count-chip">x{row.count}</i> : null}</span>
                      <span className="alert-route">{source?.name ?? "Unknown"} <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg> {target?.name ?? "Unknown"}</span>
                      <time className="mono">{clock}</time>
                      {row.simulation ? <span className="sim-pill">SIMULATION</span> : null}
                    </button>
                  );
                })}
              </div>
            )}
          </Panel>
          <Panel title="Selected node">
            {host ? (
              <SelectedNode
                host={host}
                risk={riskText}
                compromised={marked === "COMPROMISED" || (!marked && host.status === "COMPROMISED")}
                status={marked || host.status}
                neighbours={neighbours}
                stage={live && scenario.path.includes(host.id) && stageIndex >= 0 && stageIndex < 4 ? STAGE_NAMES[stageIndex] : ""}
                canAct={canLaunchAttack(role)}
                onSelect={choose}
              />
            ) : (
              <div>
                <p className="risk-line">{assets.length} nodes in the snapshot.</p>
                <ul className="conn-list">
                  {Object.entries(counts).filter(([key]) => !key.startsWith("status:")).map(([type, count]) => (
                    <li key={type}>{count} {type.toLowerCase().replaceAll("_", " ")}</li>
                  ))}
                  {Object.entries(counts).filter(([key]) => key.startsWith("status:")).map(([key, count]) => (
                    <li key={key}>{count} {key.slice(7).toLowerCase()}</li>
                  ))}
                </ul>
              </div>
            )}
          </Panel>
        </div>
      </div>
      <RoleDashboard
        role={role}
        username={username}
        assets={assets}
        alerts={alerts}
        alertCount={alertCount}
        disconnected={disconnected}
      />
    </div>
  );
}

function useQuality(): AlertQualityBody | null {
  const [quality, setQuality] = useState<AlertQualityBody | null>(null);
  useEffect(() => {
    let stop = false;
    const read = () => {
      loadAlertQuality()
        .then((body) => { if (!stop) setQuality(body); })
        .catch(() => undefined);
    };
    read();
    const timer = window.setInterval(read, 5000);
    return () => {
      stop = true;
      window.clearInterval(timer);
    };
  }, []);
  return quality;
}

function useCount(target: number): number {
  const reduced = useReducedMotion();
  const [shown, setShown] = useState(target);
  const state = useRef({ v: target, vel: 0 });
  useEffect(() => {
    if (reduced) {
      state.current = { v: target, vel: 0 };
      setShown(target);
      return;
    }
    state.current.vel = 0;
    let frame = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const dt = Math.min(0.032, (now - last) / 1000);
      last = now;
      const acc = -170 * (state.current.v - target) - 26.1 * state.current.vel;
      state.current.vel += acc * dt;
      state.current.v += state.current.vel * dt;
      if (Math.abs(state.current.v - target) < 0.35 && Math.abs(state.current.vel) < 0.35) {
        state.current.v = target;
        state.current.vel = 0;
        setShown(target);
        return;
      }
      setShown(state.current.v);
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, reduced]);
  return Math.round(shown);
}

function relativeTime(iso: string): string {
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return "Unknown";
  const minutes = Math.max(0, Math.round((Date.now() - time) / 60000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours}h ago` : "Earlier";
}

function greeting(name: string): string {
  const hour = new Date().getHours();
  const part = hour < 12 ? "Good morning" : hour < 17 ? "Good afternoon" : "Good evening";
  const label = name ? name.charAt(0).toUpperCase() + name.slice(1) : "operator";
  return `${part}, ${label}`;
}

function SelectedNode({
  host,
  risk,
  compromised,
  status,
  neighbours,
  stage,
  canAct,
  onSelect,
}: {
  host: Asset;
  risk: number;
  compromised: boolean;
  status: string;
  neighbours: Asset[];
  stage: string;
  canAct: boolean;
  onSelect: (id: string) => void;
}) {
  const shownStatus = status || (compromised ? "COMPROMISED" : host.status);
  const score = Math.max(0, Math.min(100, risk));
  return (
    <>
      <div className="ops-scroll">
        <p className="node-name">{host.name}</p>
        <p className="node-meta"><span className="badge">{sentence(host.type)}</span> <StatusBadge status={shownStatus} /></p>
        {stage ? <p className="node-stage">{stage}</p> : null}
        <p className="mono node-ip">{host.ip}</p>
        <p className="risk-label">Risk score</p>
        <p className="risk-line"><b className="stat-value risk-num">{score}</b><span className="risk-denom">/100</span></p>
        <div className="risk-bar" aria-hidden="true"><i className={shownStatus === "COMPROMISED" ? "is-bad" : shownStatus === "SUSPICIOUS" ? "is-warn" : ""} style={{ width: `${score}%` }} /></div>
        <ul className="conn-list">
          {neighbours.length === 0 ? <li>No stored connections.</li> : neighbours.map((item) => (
            <li key={item.id}>
              <button type="button" onClick={() => onSelect(item.id)}>
                <StatusBadge status={item.status} />
                <span className="conn-name">{item.name}</span>
                <span className="conn-type">{sentence(item.type)}</span>
                <span className="mono">{item.ip}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
      <div className="node-actions">
        <button type="button" className="secondary" disabled title={canAct ? "The server does not expose isolate." : "Your role cannot isolate hosts."}>Isolate</button>
        <Link className="secondary" to={`/portal/hosts/${host.id}`}>Inspect</Link>
        <button type="button" className="secondary" disabled title={canAct ? "The server does not expose restore." : "Your role cannot restore hosts."}>Restore</button>
      </div>
    </>
  );
}
