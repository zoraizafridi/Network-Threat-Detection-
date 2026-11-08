import type { FlowRow } from "./types";

export type FlowSortKey = "start" | "bytes" | "packets" | "duration";

export interface FlowFilter {
  query: string;
  label: string;
  protocol: string;
}

export const emptyFilter: FlowFilter = { query: "", label: "", protocol: "" };

export function matchesFlow(flow: FlowRow, filter: FlowFilter): boolean {
  if (filter.label && flow.label !== filter.label) return false;
  if (filter.protocol && flow.protocol !== filter.protocol) return false;
  const needle = filter.query.trim().toLowerCase();
  if (!needle) return true;
  const haystack = `${flow.srcIp} ${flow.dstIp} ${flow.srcPort} ${flow.dstPort} ${flow.label} ${flow.flags.join(" ")}`;
  return haystack.toLowerCase().includes(needle);
}

function compare(sortKey: FlowSortKey) {
  return (a: FlowRow, b: FlowRow): number => {
    let delta: number;
    switch (sortKey) {
      case "bytes":
        delta = b.bytesOut - a.bytesOut;
        break;
      case "packets":
        delta = b.packets - a.packets;
        break;
      case "duration":
        delta = b.durationMs - a.durationMs;
        break;
      default:
        delta = new Date(b.startTime).getTime() - new Date(a.startTime).getTime();
    }
    if (delta !== 0 && !Number.isNaN(delta)) return delta;
    return a.id.localeCompare(b.id);
  };
}

export function filterFlows(rows: FlowRow[], filter: FlowFilter, sortKey: FlowSortKey = "start"): FlowRow[] {
  return rows.filter((flow) => matchesFlow(flow, filter)).slice().sort(compare(sortKey));
}

export interface FlowSummary {
  flows: number;
  open: number;
  bytes: number;
  packets: number;
  labels: { label: string; count: number }[];
  protocols: { protocol: string; count: number }[];
}

export function summarizeFlows(rows: FlowRow[]): FlowSummary {
  const labels = new Map<string, number>();
  const protocols = new Map<string, number>();
  let bytes = 0;
  let packets = 0;
  let open = 0;
  for (const flow of rows) {
    bytes += flow.bytesOut;
    packets += flow.packets;
    if (!flow.ended) open += 1;
    labels.set(flow.label, (labels.get(flow.label) ?? 0) + 1);
    protocols.set(flow.protocol, (protocols.get(flow.protocol) ?? 0) + 1);
  }
  const rank = (a: { count: number; label: string }, b: { count: number; label: string }) =>
    b.count - a.count || a.label.localeCompare(b.label);
  return {
    flows: rows.length,
    open,
    bytes,
    packets,
    labels: [...labels].map(([label, count]) => ({ label, count })).sort(rank),
    protocols: [...protocols]
      .map(([protocol, count]) => ({ protocol, count }))
      .sort((a, b) => b.count - a.count || a.protocol.localeCompare(b.protocol)),
  };
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const power = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
  const scaled = value / 1024 ** power;
  const digits = power === 0 || scaled >= 100 ? 0 : 1;
  return `${scaled.toFixed(digits)} ${units[power]}`;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "0s";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes}m ${rest}s`;
}

export function flowLabelOptions(rows: FlowRow[]): string[] {
  return [...new Set(rows.map((flow) => flow.label))].sort((a, b) => a.localeCompare(b));
}

export function flowProtocolOptions(rows: FlowRow[]): string[] {
  return [...new Set(rows.map((flow) => flow.protocol))].sort((a, b) => a.localeCompare(b));
}
