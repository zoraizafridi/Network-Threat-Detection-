import { useEffect, useMemo, useRef, useState } from "react";
import { HttpStatusError, runPlan } from "../api";
import { EmptyState, MapPanel, Page, Panel, StatusBadge } from "../components/ui";
import { NetworkMap } from "../components/NetworkMap";
import { statusLabel } from "../format";
import { accessDenied, canRunPlanner } from "../permissions";
import { useApp } from "../store";
import type { Asset } from "../types";
import type { Asset } from "../types";
import type { PlanBody, SocTeam } from "../types";

interface SavedRun {
  at: number;
  durationMs: number;
  excluded: string[];
  capacities: SocTeam[];
  plan: PlanBody;
}

interface DraftAssign {
  taskId: string;
  team: string;
}

export function PlannerPage() {
  const role = useApp((state) => state.user?.role ?? "");
  const assets = useApp((state) => state.assets);
  const teams = useApp((state) => state.teams);
  const selectedId = useApp((state) => state.selectedId);
  const setPlannerView = useApp((state) => state.setPlannerView);
  const setNotice = useApp((state) => state.setNotice);
  const [excluded, setExcluded] = useState<string[]>([]);
  const [capacities, setCapacities] = useState<SocTeam[]>([]);
  const [query, setQuery] = useState("");
  const [pick, setPick] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState("");
  const [plan, setPlan] = useState<PlanBody | null>(null);
  const [ranAt, setRanAt] = useState(0);
  const [durationMs, setDurationMs] = useState(0);
  const [stale, setStale] = useState(false);
  const [showMap, setShowMap] = useState(true);
  const [hover, setHover] = useState<string | null>(null);
  const [details, setDetails] = useState(false);
  const [groupTeam, setGroupTeam] = useState(false);
  const [drafts, setDrafts] = useState<DraftAssign[]>([]);
  const [history, setHistory] = useState<SavedRun[]>([]);
  const [compare, setCompare] = useState(false);
  const setSelectedIdPlanner = useApp((state) => state.setSelectedId);

  useEffect(() => {
    if (teams.length && capacities.length === 0) setCapacities(teams);
  }, [teams, capacities.length]);

  const pickArmed = useRef(false);
  useEffect(() => {
    if (!pick) {
      pickArmed.current = false;
      return;
    }
    if (!pickArmed.current) {
      pickArmed.current = true;
      return;
    }
    if (!selectedId) return;
    setExcluded((current) => (current.includes(selectedId) ? current.filter((id) => id !== selectedId) : [...current, selectedId]));
    setStale(true);
  }, [pick, selectedId]);

  const pairs = useMemo(() => {
    return (plan?.backbone.linkEnds ?? []).map((end) => ({
      id: end.id,
      source: end.sourceId,
      target: end.targetId,
    }));
  }, [plan]);

  useEffect(() => {
    setPlannerView({
      excluded,
      unreachable: plan?.backbone.unreachable ?? [],
      pairs: showMap ? pairs : [],
      hover,
      show: Boolean(plan) && showMap,
    });
    return () => setPlannerView(null);
  }, [excluded, plan, pairs, hover, showMap, setPlannerView]);

  if (!canRunPlanner(role)) {
    return <p>{accessDenied(role)}</p>;
  }

  const nameOf = (id: string) => assets.find((asset) => asset.id === id)?.name ?? id;
  const filtered = assets.filter((asset) => {
    const needle = query.trim().toLowerCase();
    if (!needle) return true;
    return asset.name.toLowerCase().includes(needle) || asset.type.toLowerCase().includes(needle);
  });
  const grouped = ["ROUTER", "SERVER", "WORKSTATION", "IOT_DEVICE"].map((type) => ({
    type,
    rows: filtered.filter((asset) => asset.type === type),
  }));

  async function run() {
    setBusy(true);
    setFailed("");
    setNotice("");
    const started = performance.now();
    try {
      const body = await runPlan({ excludedHostIds: excluded, teamCapacities: capacities });
      const duration = Math.round(performance.now() - started);
      setPlan(body);
      setRanAt(Date.now());
      setDurationMs(duration);
      setStale(false);
      setDrafts([]);
      setHistory((current) => [{ at: Date.now(), durationMs: duration, excluded: excluded.slice(), capacities: capacities.slice(), plan: body }, ...current].slice(0, 5));
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 403) setNotice(accessDenied(role));
      else setFailed("The server did not return a plan.");
    } finally {
      setBusy(false);
    }
  }

  function resetInputs() {
    setExcluded([]);
    setCapacities(teams);
    setStale(Boolean(plan));
    setPick(false);
  }

  const tasks = (plan?.assignment.teams ?? []).flatMap((team) =>
    (team.taskDetails ?? team.tasks.map((id) => ({ id, hostId: "", hostName: "", value: 0, cost: 0 }))).map((task) => ({
      ...task,
      team: drafts.find((row) => row.taskId === task.id)?.team ?? team.team,
      manual: drafts.some((row) => row.taskId === task.id),
    })),
  );
  const previous = history[1];
  const currentRun = history[0];

  function delta(before: number, after: number, lowerIsBetter: boolean) {
    const change = after - before;
    if (change === 0) return { text: "0", tone: "neutral" };
    const better = lowerIsBetter ? change < 0 : change > 0;
    return { text: `${change > 0 ? "+" : ""}${change}`, tone: better ? "ok" : "critical" };
  }

  return (
    <Page title="Planner" description="Choose hosts and team capacity, then run the server response plan.">
      <div className="row">
        <button type="button" className="primary" onClick={() => void run()} disabled={busy}>{busy ? "Running" : "Run response"}</button>
        {stale ? <span className="badge warn">Results out of date</span> : null}
        {ranAt ? <span className="muted">Last run {new Date(ranAt).toLocaleTimeString()} · {durationMs} ms</span> : null}
      </div>
      <div className="plan-grid">
        <Panel className="span-3" title="Plan inputs" subtitle="Sent to the server on the next run">
          <label>Search hosts <input value={query} onChange={(event) => setQuery(event.target.value)} /></label>
          <label className="row"><input type="checkbox" checked={pick} onChange={(event) => setPick(event.target.checked)} /> Pick on map</label>
          <p className="muted">{excluded.length} excluded</p>
          <div className="host-pick">
            {grouped.map((group) => group.rows.length === 0 ? null : (
              <div key={group.type}>
                <p className="muted">{statusLabel(group.type)}</p>
                {group.rows.map((asset) => (
                  <label key={asset.id}>
                    <input
                      type="checkbox"
                      checked={excluded.includes(asset.id)}
                      onChange={() => {
                        setExcluded((current) => current.includes(asset.id) ? current.filter((id) => id !== asset.id) : [...current, asset.id]);
                        setStale(true);
                      }}
                    />
                    <StatusBadge status={asset.status} />
                    <span>{asset.name}</span>
                    <span className="muted">{statusLabel(asset.type)}</span>
                  </label>
                ))}
              </div>
            ))}
          </div>
          <p>Teams</p>
          {capacities.length === 0 ? <p className="muted">No teams reported yet.</p> : capacities.map((team) => (
            <label key={team.name}>
              {team.name}
              <input
                type="number"
                min={1}
                value={team.capacity}
                title="Capacity is the cost this team can take. The server uses it on the next run."
                onChange={(event) => {
                  const capacity = Number(event.target.value);
                  setCapacities((current) => current.map((row) => row.name === team.name ? { ...row, capacity } : row));
                  setStale(true);
                }}
              />
            </label>
          ))}
          <div className="row">
            <button type="button" className="primary" onClick={() => void run()} disabled={busy}>Run response</button>
            <button type="button" className="secondary" onClick={resetInputs}>Reset inputs</button>
          </div>
        </Panel>
        <MapPanel className="span-6" title="Network topology" subtitle="Excluded, unreachable, and backbone">
          <NetworkMap assets={assets} selectedId={selectedId} onSelect={(id) => { setSelectedIdPlanner(id || null); }} />
        </MapPanel>
        <Panel className="span-3" title="Result" subtitle="Returned by the server">
          {!plan && !failed ? <EmptyState>Run the response to see the backbone and assignments.</EmptyState> : null}
          {failed ? <p>{failed} <button type="button" onClick={() => void run()}>Retry</button></p> : null}
          {plan ? (
            <>
              <p>Connected <StatusBadge status={plan.backbone.connected ? "HEALTHY" : "CRITICAL"} /></p>
              <p>Backbone cost <b className="mono">{plan.backbone.totalWeight}</b></p>
              <p>Value protected <b className="mono">{plan.assignment.totalValue}</b></p>
              <p>Unreachable hosts {plan.backbone.unreachable.length === 0 ? <StatusBadge status="HEALTHY" /> : plan.backbone.unreachable.map((id) => (
                <button key={id} type="button" className="secondary" onClick={() => useApp.getState().setSelectedId(id)}>{nameOf(id)}</button>
              ))}</p>
              {plan.backbone.unreachable.length === 0 ? <p>All hosts reachable</p> : null}
              <p>Excluded hosts <b className="mono">{excluded.length}</b></p>
              <button type="button" className="secondary" onClick={() => setDetails((value) => !value)}>Details</button>
              {details ? <p className="muted" title="How many assignment states the server explored.">Search states explored {plan.assignment.stateCount}</p> : null}
              <button type="button" className="secondary" onClick={() => setShowMap((value) => !value)}>{showMap ? "Hide backbone" : "Show on map"}</button>
              <ul>
                {(plan.backbone.linkEnds ?? []).map((end) => (
                  <li key={end.id} onMouseEnter={() => setHover(end.id)} onMouseLeave={() => setHover(null)} title={end.id}>
                    {end.sourceName} — {end.targetName}
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </Panel>
        <Panel className="span-12" title="Task assignments" subtitle="Team changes stay on this page until a new run" action={<button type="button" className="secondary" onClick={() => setGroupTeam((value) => !value)}>{groupTeam ? "Flat list" : "Group by team"}</button>}>
          {tasks.length === 0 ? <EmptyState>No tasks in this plan.</EmptyState> : (
            <table>
              <thead>
                <tr><th>Task</th><th>Host</th><th>Team</th><th>Value</th><th>Status</th></tr>
              </thead>
              <tbody>
                {tasks.map((task) => (
                  <tr key={task.id} className={task.manual ? "is-manual" : undefined}>
                    <td title={task.id}>{task.hostName ? `Mitigate risk on ${task.hostName}` : task.id}</td>
                    <td><button type="button" className="secondary" onClick={() => task.hostId && useApp.getState().setSelectedId(task.hostId)}>{task.hostName || "Unknown"}</button></td>
                    <td>
                      <select
                        value={task.team}
                        onChange={(event) => {
                          const team = event.target.value;
                          setDrafts((current) => [...current.filter((row) => row.taskId !== task.id), { taskId: task.id, team }]);
                        }}
                      >
                        {(plan?.assignment.teams ?? []).map((row) => <option key={row.team} value={row.team}>{row.team}</option>)}
                      </select>
                      {task.manual ? <span className="badge">Manual</span> : null}
                    </td>
                    <td className="mono">{task.value}</td>
                    <td>{task.manual ? "Draft, not saved to server" : "Assigned"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="row">
            <button
              type="button"
              className="secondary"
              onClick={() => {
                const text = tasks.map((task) => `${task.hostName || task.id}\t${task.team}\t${task.value}`).join("\n");
                const blob = new Blob([text], { type: "text/plain" });
                const url = URL.createObjectURL(blob);
                const link = document.createElement("a");
                link.href = url;
                link.download = "assignment-draft.txt";
                link.click();
                URL.revokeObjectURL(url);
              }}
            >
              Export draft
            </button>
            <button type="button" onClick={() => setDrafts([])}>Revert</button>
          </div>
          <p className="muted">Apply is a draft. The server has no request that saves a manual team change.</p>
        </Panel>
        <Panel className="span-12" title="Compare runs" subtitle="Two real server results, diffed here" action={<button type="button" className="secondary" onClick={() => setCompare((value) => !value)}>{compare || history.length > 1 ? "History" : "Waiting for a second run"}</button>}>
          {history.length < 2 ? <p className="muted">Run the response twice to compare.</p> : (
            <table>
              <thead><tr><th>Metric</th><th>Previous</th><th>Current</th><th>Delta</th></tr></thead>
              <tbody>
                {[
                  ["Backbone cost", previous.plan.backbone.totalWeight, currentRun.plan.backbone.totalWeight, true],
                  ["Value protected", previous.plan.assignment.totalValue, currentRun.plan.assignment.totalValue, false],
                  ["Unreachable", previous.plan.backbone.unreachable.length, currentRun.plan.backbone.unreachable.length, true],
                  ["Excluded", previous.excluded.length, currentRun.excluded.length, false],
                ].map(([label, before, after, lower]) => {
                  const chip = delta(Number(before), Number(after), Boolean(lower));
                  return (
                    <tr key={String(label)}>
                      <td>{label}</td>
                      <td className="mono">{String(before)}</td>
                      <td className="mono">{String(after)}</td>
                      <td><span className={`badge ${chip.tone === "ok" ? "" : chip.tone === "critical" ? "critical" : ""}`}>{chip.text}</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <ul>
            {history.map((run) => (
              <li key={run.at}>
                <button type="button" onClick={() => { setPlan(run.plan); setExcluded(run.excluded); setCapacities(run.capacities); setStale(false); }}>
                  {new Date(run.at).toLocaleTimeString()} · {run.excluded.length} hosts excluded
                </button>
                <button type="button" className="secondary" onClick={() => { setExcluded(run.excluded); setCapacities(run.capacities); setStale(true); }}>Restore these inputs</button>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
      <p className="muted">Legend: dashed ring is excluded, amber ring is unreachable, blue links are the backbone.</p>
    </Page>
  );
}
