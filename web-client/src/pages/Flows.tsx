import { useCallback, useEffect, useMemo, useState } from "react";
import { HttpStatusError, loadFlowHistory, loadFlows } from "../api";
import { EmptyState, Page, Panel, StatusBadge } from "../components/ui";
import { clockTime } from "../format";
import {
  filterFlows,
  flowLabelOptions,
  flowProtocolOptions,
  formatBytes,
  formatDuration,
  summarizeFlows,
  type FlowFilter,
  type FlowSortKey,
} from "../flows";
import type { FlowRow } from "../types";

const REFRESH_MS = 3000;
const ROW_LIMIT = 500;

type FlowSource = "live" | "stored";

export function FlowsPage() {
  const [rows, setRows] = useState<FlowRow[]>([]);
  const [failed, setFailed] = useState(false);
  const [storeOff, setStoreOff] = useState(false);
  const [source, setSource] = useState<FlowSource>("live");
  const [live, setLive] = useState(true);
  const [reload, setReload] = useState(0);
  const [filter, setFilter] = useState<FlowFilter>({ query: "", label: "", protocol: "" });
  const [sortKey, setSortKey] = useState<FlowSortKey>("start");

  const pull = useCallback(async (cancelled: () => boolean) => {
    try {
      const body = source === "stored" ? await loadFlowHistory(ROW_LIMIT) : await loadFlows(ROW_LIMIT);
      if (!cancelled()) {
        setRows(body);
        setFailed(false);
        setStoreOff(false);
      }
    } catch (error) {
      if (!cancelled()) {
        setFailed(true);
        setStoreOff(source === "stored" && error instanceof HttpStatusError && error.status === 503);
      }
    }
  }, [source]);

  useEffect(() => {
    let stop = false;
    let timer: number | undefined;
    const cancelled = () => stop;
    async function tick() {
      await pull(cancelled);
      if (!stop && live && source === "live") {
        timer = window.setTimeout(tick, REFRESH_MS);
      }
    }
    tick();
    return () => {
      stop = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [live, pull, reload, source]);

  const visible = useMemo(() => filterFlows(rows, filter, sortKey), [rows, filter, sortKey]);
  const summary = useMemo(() => summarizeFlows(rows), [rows]);
  const labelOptions = useMemo(() => flowLabelOptions(rows), [rows]);
  const protocolOptions = useMemo(() => flowProtocolOptions(rows), [rows]);

  function sortHeader(key: FlowSortKey, text: string) {
    return (
      <th>
        <button type="button" className={sortKey === key ? "is-active" : undefined} onClick={() => setSortKey(key)}>
          {text}
        </button>
      </th>
    );
  }

  return (
    <Page title="Flows" description="Connection records from the live feed, or the ones that reached the durable store.">
      <div className="stat-row">
        <article className="stat-tile"><strong className="stat-value">{summary.flows}</strong><span>Records</span></article>
        <article className="stat-tile"><strong className="stat-value">{summary.open}</strong><span>Still open</span></article>
        <article className="stat-tile"><strong className="stat-value">{formatBytes(summary.bytes)}</strong><span>Bytes out</span></article>
        <article className="stat-tile"><strong className="stat-value">{summary.packets}</strong><span>Packets</span></article>
      </div>
      <div className="row no-print">
        <div className="row" role="group" aria-label="Flow source">
          <button type="button" aria-pressed={source === "live"} className={source === "live" ? undefined : "secondary"} onClick={() => setSource("live")}>
            Live
          </button>
          <button type="button" aria-pressed={source === "stored"} className={source === "stored" ? undefined : "secondary"} onClick={() => setSource("stored")}>
            Stored
          </button>
        </div>
        <input
          value={filter.query}
          aria-label="Search flows"
          placeholder="Address, port or label"
          onChange={(event) => setFilter((current) => ({ ...current, query: event.target.value }))}
        />
        <select
          value={filter.label}
          aria-label="Label"
          onChange={(event) => setFilter((current) => ({ ...current, label: event.target.value }))}
        >
          <option value="">All labels</option>
          {labelOptions.map((option) => <option key={option} value={option}>{option}</option>)}
        </select>
        <select
          value={filter.protocol}
          aria-label="Protocol"
          onChange={(event) => setFilter((current) => ({ ...current, protocol: event.target.value }))}
        >
          <option value="">All protocols</option>
          {protocolOptions.map((option) => <option key={option} value={option}>{option}</option>)}
        </select>
        <button type="button" className="secondary" onClick={() => setLive((value) => !value)}>
          {live ? "Pause" : "Resume"}
        </button>
        <button type="button" onClick={() => setReload((value) => value + 1)}>Refresh</button>
      </div>
      <div className="board-12">
        <Panel
          className="span-8"
          title="Connection records"
          subtitle={
            source === "stored"
              ? "Read from the durable store"
              : live
                ? "Polling every 3 seconds"
                : "Paused"
          }
        >
          {failed ? (
            <p>
              {storeOff
                ? "The durable store is off. Set persistence.enabled=true to keep flows across restarts."
                : "The flow table could not be loaded. "}
              <button type="button" onClick={() => setReload((value) => value + 1)}>Retry</button>
            </p>
          ) : null}
          {!failed && visible.length === 0 ? (
            <EmptyState>
              {source === "stored"
                ? "No stored flows yet. They appear once the store is on and flows close."
                : rows.length === 0
                  ? "No flows yet. Start the simulator to generate traffic."
                  : "No flows match these filters."}
            </EmptyState>
          ) : null}
          {visible.length > 0 ? (
            <table className="flow-table">
              <thead>
                <tr>
                  {sortHeader("start", "Start")}
                  <th>Label</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Proto</th>
                  {sortHeader("bytes", "Bytes")}
                  {sortHeader("packets", "Packets")}
                  {sortHeader("duration", "Duration")}
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((flow) => (
                  <tr key={flow.id}>
                    <td className="mono" title={`${flow.startTime} - ${flow.endTime}`}>{clockTime(flow.startTime)}</td>
                    <td><StatusBadge status={flow.label} /></td>
                    <td>{flow.srcIp}<br /><span className="mono muted">{flow.srcPort}</span></td>
                    <td>{flow.dstIp}<br /><span className="mono muted">{flow.dstPort}</span></td>
                    <td className="mono">{flow.protocol}</td>
                    <td className="mono" title={`${flow.bytesOut} bytes`}>{formatBytes(flow.bytesOut)}</td>
                    <td className="mono">{flow.packets}</td>
                    <td className="mono">{formatDuration(flow.durationMs)}</td>
                    <td>{flow.ended ? "Closed" : "Open"}{flow.flags.includes("FAILED") ? " / failed" : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
          {visible.length > 0 && visible.length < rows.length ? (
            <p className="muted">{visible.length} of {rows.length} records match.</p>
          ) : null}
        </Panel>
        <Panel className="span-4" title="Captured labels" subtitle="Shown records grouped by label">
          {summary.labels.length === 0 ? <EmptyState>Nothing captured yet.</EmptyState> : (
            <ul className="flow-labels">
              {summary.labels.map((row) => (
                <li key={row.label}><StatusBadge status={row.label} /> <span className="mono">{row.count}</span></li>
              ))}
            </ul>
          )}
          <p className="muted">
            Bytes in stay at zero: the simulator only emits one-directional events, so no reply
            traffic is ever claimed.
          </p>
        </Panel>
      </div>
    </Page>
  );
}
