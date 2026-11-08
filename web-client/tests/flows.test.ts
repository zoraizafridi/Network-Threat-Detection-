import { describe, expect, test } from "vitest";
import {
  emptyFilter,
  filterFlows,
  flowLabelOptions,
  flowProtocolOptions,
  formatBytes,
  formatDuration,
  matchesFlow,
  summarizeFlows,
} from "../src/flows";
import type { FlowRow } from "../src/types";

function flow(overrides: Partial<FlowRow> = {}): FlowRow {
  return {
    id: "f1",
    srcIp: "10.0.0.5",
    dstIp: "10.0.0.9",
    srcPort: 41000,
    dstPort: 443,
    protocol: "TCP",
    bytesOut: 1000,
    bytesIn: 0,
    packets: 4,
    startTime: "2026-11-05T12:00:00Z",
    endTime: "2026-11-05T12:00:04Z",
    durationMs: 4000,
    flags: ["OK"],
    label: "NORMAL",
    simulated: false,
    ended: true,
    ...overrides,
  };
}

describe("flow filtering", () => {
  test("an empty filter keeps every record", () => {
    const rows = [flow(), flow({ id: "f2", label: "PORT_SCAN" })];
    expect(filterFlows(rows, emptyFilter)).toHaveLength(2);
  });

  test("the search box matches addresses, ports, labels and flags", () => {
    const rows = [
      flow({ id: "f1" }),
      flow({ id: "f2", srcIp: "10.0.0.7", dstPort: 8080, label: "PORT_SCAN" }),
      flow({ id: "f3", label: "DOS_FLOOD", flags: ["OK", "FAILED"], dstPort: 53, protocol: "UDP" }),
    ];

    expect(filterFlows(rows, { ...emptyFilter, query: "8080" }).map((row) => row.id)).toEqual(["f2"]);
    expect(filterFlows(rows, { ...emptyFilter, query: "port_scan" }).map((row) => row.id)).toEqual(["f2"]);
    expect(filterFlows(rows, { ...emptyFilter, query: "10.0.0.7" }).map((row) => row.id)).toEqual(["f2"]);
    expect(filterFlows(rows, { ...emptyFilter, query: "failed" }).map((row) => row.id)).toEqual(["f3"]);
    expect(filterFlows(rows, { ...emptyFilter, query: "   " })).toHaveLength(3);
  });

  test("label and protocol select exactly that slice", () => {
    const rows = [flow({ id: "f1" }), flow({ id: "f2", label: "DOS_FLOOD", protocol: "UDP" })];

    expect(filterFlows(rows, { ...emptyFilter, label: "DOS_FLOOD" }).map((row) => row.id)).toEqual(["f2"]);
    expect(filterFlows(rows, { ...emptyFilter, protocol: "UDP" }).map((row) => row.id)).toEqual(["f2"]);
    expect(filterFlows(rows, { ...emptyFilter, label: "DOS_FLOOD", protocol: "TCP" })).toHaveLength(0);
  });

  test("matchesFlow never mutates the input", () => {
    const row = flow();
    const before = { ...row };
    matchesFlow(row, { query: "nope", label: "", protocol: "" });
    expect(row).toEqual(before);
  });
});

describe("flow sorting", () => {
  const rows = [
    flow({ id: "a", bytesOut: 100, packets: 9, durationMs: 9000, startTime: "2026-11-05T12:00:00Z" }),
    flow({ id: "b", bytesOut: 900, packets: 1, durationMs: 1000, startTime: "2026-11-05T12:05:00Z" }),
    flow({ id: "c", bytesOut: 500, packets: 5, durationMs: 5000, startTime: "2026-11-05T12:02:00Z" }),
  ];

  test("start sorts newest first", () => {
    expect(filterFlows(rows, emptyFilter, "start").map((row) => row.id)).toEqual(["b", "c", "a"]);
  });

  test("bytes, packets and duration sort largest first", () => {
    expect(filterFlows(rows, emptyFilter, "bytes").map((row) => row.id)).toEqual(["b", "c", "a"]);
    expect(filterFlows(rows, emptyFilter, "packets").map((row) => row.id)).toEqual(["a", "c", "b"]);
    expect(filterFlows(rows, emptyFilter, "duration").map((row) => row.id)).toEqual(["a", "c", "b"]);
  });

  test("equal keys keep a stable order so polling does not shuffle rows", () => {
    const tied = [
      flow({ id: "f9", bytesOut: 10 }),
      flow({ id: "f2", bytesOut: 10 }),
      flow({ id: "f5", bytesOut: 10 }),
    ];
    expect(filterFlows(tied, emptyFilter, "bytes").map((row) => row.id)).toEqual(["f2", "f5", "f9"]);
    expect(filterFlows(tied, emptyFilter, "bytes").map((row) => row.id)).toEqual(["f2", "f5", "f9"]);
  });
});

describe("flow summary", () => {
  test("counts records, open flows, bytes, packets and labels", () => {
    const rows = [
      flow({ id: "f1", label: "NORMAL", bytesOut: 100, packets: 2 }),
      flow({ id: "f2", label: "NORMAL", bytesOut: 50, packets: 1, ended: false }),
      flow({ id: "f3", label: "DOS_FLOOD", bytesOut: 400, packets: 7, protocol: "UDP" }),
    ];

    const summary = summarizeFlows(rows);

    expect(summary.flows).toBe(3);
    expect(summary.open).toBe(1);
    expect(summary.bytes).toBe(550);
    expect(summary.packets).toBe(10);
    expect(summary.labels).toEqual([
      { label: "NORMAL", count: 2 },
      { label: "DOS_FLOOD", count: 1 },
    ]);
    expect(summary.protocols).toEqual([
      { protocol: "TCP", count: 2 },
      { protocol: "UDP", count: 1 },
    ]);
  });

  test("an empty table summarises to zeros rather than throwing", () => {
    expect(summarizeFlows([])).toEqual({
      flows: 0,
      open: 0,
      bytes: 0,
      packets: 0,
      labels: [],
      protocols: [],
    });
  });
});

describe("flow formatting", () => {
  test("bytes scale through the unit ladder", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(-5)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(1024 * 1024 * 3.5)).toBe("3.5 MB");
    expect(formatBytes(1024 ** 3 * 120)).toBe("120 GB");
  });

  test("durations stay readable from milliseconds to minutes", () => {
    expect(formatDuration(0)).toBe("0s");
    expect(formatDuration(250)).toBe("250ms");
    expect(formatDuration(4200)).toBe("4.2s");
    expect(formatDuration(45500)).toBe("46s");
    expect(formatDuration(125000)).toBe("2m 5s");
  });

  test("filter options are unique and sorted", () => {
    const rows = [flow({ label: "NORMAL" }), flow({ id: "f2", label: "DOS_FLOOD" }), flow({ id: "f3" })];
    expect(flowLabelOptions(rows)).toEqual(["DOS_FLOOD", "NORMAL"]);
    expect(flowProtocolOptions([...rows, flow({ id: "f4", protocol: "UDP" })])).toEqual(["TCP", "UDP"]);
  });
});
