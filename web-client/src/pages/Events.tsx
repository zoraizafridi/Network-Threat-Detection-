import { useCallback, useEffect, useMemo, useState } from "react";
import {
  HttpStatusError,
  exportUrl,
  loadAlertQuality,
  searchEvents,
  type AlertQualityBody,
  type EventSearchBody,
} from "../api";
import { EmptyState, Page, Panel, StatusBadge } from "../components/ui";
import { foldLabel, type FeedAlert } from "../alerts";
import { attackLabel, clockTime, relativeTime } from "../format";

const PAGE = 50;
const TAIL_MS = 3000;

const WINDOWS: { label: string; minutes: number }[] = [
  { label: "Any time", minutes: 0 },
  { label: "Last 15 minutes", minutes: 15 },
  { label: "Last hour", minutes: 60 },
  { label: "Last 24 hours", minutes: 1440 },
];

type SimulatedFilter = "any" | "live" | "simulated";

export function EventsPage() {
  const [text, setText] = useState("");
  const [severity, setSeverity] = useState("");
  const [attackType, setAttackType] = useState("");
  const [detector, setDetector] = useState("");
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [simulated, setSimulated] = useState<SimulatedFilter>("any");
  const [windowMinutes, setWindowMinutes] = useState(0);
  const [offset, setOffset] = useState(0);
  const [result, setResult] = useState<EventSearchBody | null>(null);
  const [selected, setSelected] = useState<FeedAlert | null>(null);
  const [failed, setFailed] = useState("");
  const [tail, setTail] = useState(true);
  const [tick, setTick] = useState(0);
  const [quality, setQuality] = useState<AlertQualityBody | null>(null);

  const from = useMemo(() => {
    if (windowMinutes <= 0) return undefined;
    return new Date(Date.now() - windowMinutes * 60_000).toISOString();
  }, [windowMinutes, tick]);

  const filter = useMemo(
    () => ({
      text,
      severity,
      attackType,
      detector,
      source,
      target,
      simulated: simulated === "any" ? undefined : simulated === "simulated",
      from,
      limit: PAGE,
      offset,
    }),
    [text, severity, attackType, detector, source, target, simulated, from, offset],
  );

  const pull = useCallback(async () => {
    try {
      const body = await searchEvents(filter);
      setResult(body);
      setFailed("");
    } catch (error) {
      setFailed(
        error instanceof HttpStatusError && error.status === 400
          ? "One of these filters is not valid. Clear it and search again."
          : "The event search could not be reached.",
      );
    }
  }, [filter]);

  useEffect(() => {
    void pull();
  }, [pull, tick]);

  useEffect(() => {
    if (!tail) return undefined;
    const timer = window.setInterval(() => setTick((value) => value + 1), TAIL_MS);
    return () => window.clearInterval(timer);
  }, [tail]);

  useEffect(() => {
    loadAlertQuality().then(setQuality).catch(() => setQuality(null));
  }, []);

  const total = result?.total ?? 0;
  const shown = result?.events ?? [];
  const first = total === 0 ? 0 : offset + 1;
  const last = offset + shown.length;

  function reset<T>(setter: (value: T) => void) {
    return (value: T) => {
      setOffset(0);
      setter(value);
    };
  }

  return (
    <Page
      title="Events"
      description="Search the detection history. One row per fact, with the repeats folded into its count."
    >
      {quality ? (
        <section className="quality-strip" aria-label="Event totals">
          <span><b>{quality.delivered}</b> delivered</span>
          <span><b>{quality.folded}</b> folded repeats</span>
          <span><b>{quality.suppressed}</b> suppressed</span>
          <span><b>{total}</b> match this search</span>
        </section>
      ) : null}

      <div className="row no-print">
        <a href={exportUrl("events", "csv")} download>Export CSV</a>
        <a href={exportUrl("events", "json")} download>Export JSON</a>
        <input
          value={text}
          aria-label="Search events"
          placeholder="Address, detector or text"
          onChange={(event) => reset(setText)(event.target.value)}
        />
        <select value={severity} aria-label="Severity" onChange={(event) => reset(setSeverity)(event.target.value)}>
          <option value="">All severities</option>
          <option value="LOW">Low</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
        <select value={attackType} aria-label="Attack type" onChange={(event) => reset(setAttackType)(event.target.value)}>
          <option value="">All types</option>
          <option value="PORT_SCAN">Port scan</option>
          <option value="BRUTE_FORCE">Brute force</option>
          <option value="DOS_FLOOD">DoS flood</option>
          <option value="DATA_TRANSFER">Data transfer</option>
        </select>
        <input value={detector} aria-label="Detector" placeholder="Detector" onChange={(event) => reset(setDetector)(event.target.value)} />
        <input value={source} aria-label="Source" placeholder="Source" onChange={(event) => reset(setSource)(event.target.value)} />
        <input value={target} aria-label="Target" placeholder="Target" onChange={(event) => reset(setTarget)(event.target.value)} />
        <select
          value={simulated}
          aria-label="Traffic source"
          onChange={(event) => reset(setSimulated)(event.target.value as SimulatedFilter)}
        >
          <option value="any">Live and imported</option>
          <option value="live">Live only</option>
          <option value="simulated">Imported only</option>
        </select>
        <select
          value={windowMinutes}
          aria-label="Time range"
          onChange={(event) => reset(setWindowMinutes)(Number(event.target.value))}
        >
          {WINDOWS.map((option) => (
            <option key={option.minutes} value={option.minutes}>{option.label}</option>
          ))}
        </select>
        <button type="button" className="secondary" onClick={() => setTail((value) => !value)} aria-pressed={tail}>
          {tail ? "Pause tail" : "Resume tail"}
        </button>
        <button type="button" onClick={() => void pull()}>Search</button>
      </div>

      {failed ? <p className="notice">{failed}</p> : null}

      <div className="board-12">
        <Panel
          className="span-8"
          title="Matching events"
          subtitle={tail ? `Newest first, tailing every 3 seconds` : "Newest first, tail paused"}
        >
          {shown.length === 0 ? (
            <EmptyState>
              {total === 0 ? "No events match these filters." : "No events on this page."}
            </EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Detector</th>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Target</th>
                  <th>Count</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((event) => (
                  <tr key={event.id} onClick={() => setSelected(event)} data-selected={selected?.id === event.id}>
                    <td className="mono" title={event.timestamp}>{clockTime(event.timestamp)}</td>
                    <td><StatusBadge status={event.severity} /></td>
                    <td>{event.detectorName}</td>
                    <td>{attackLabel(event.attackType)}</td>
                    <td>{event.sourceIp}</td>
                    <td>{event.targetIp}</td>
                    <td className="mono">{foldLabel(event)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="row pager">
            <button type="button" className="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
              Previous
            </button>
            <span className="muted">{total === 0 ? "No matches" : `${first} to ${last} of ${total}`}</span>
            <button type="button" className="secondary" disabled={last >= total} onClick={() => setOffset(offset + PAGE)}>
              Next
            </button>
          </div>
        </Panel>

        <Panel className="span-4" title="Selected event" subtitle="The full row behind the search hit.">
          {selected ? (
            <>
              <p><StatusBadge status={selected.severity} /> {attackLabel(selected.attackType)}</p>
              <p className="muted">{selected.description}</p>
              <table>
                <tbody>
                  <tr><td>Detector</td><td>{selected.detectorName}</td></tr>
                  <tr><td>Route</td><td className="mono">{selected.sourceIp} to {selected.targetIp}</td></tr>
                  <tr><td>First seen</td><td className="mono">{selected.firstSeen ? clockTime(selected.firstSeen) : "unknown"}</td></tr>
                  <tr><td>Last seen</td><td className="mono" title={selected.lastSeen}>{selected.lastSeen ? relativeTime(selected.lastSeen) : "unknown"}</td></tr>
                  <tr><td>Occurrences</td><td className="mono">{selected.occurrences ?? 1}</td></tr>
                  <tr><td>Status</td><td><StatusBadge status={selected.status ?? "NEW"} /></td></tr>
                  <tr><td>Origin</td><td>{selected.simulated ? "Imported capture" : "Live traffic"}</td></tr>
                </tbody>
              </table>
            </>
          ) : (
            <EmptyState>Select a row to read it.</EmptyState>
          )}
        </Panel>
      </div>
    </Page>
  );
}
