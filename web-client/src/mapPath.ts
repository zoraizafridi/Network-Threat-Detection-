import type { Asset } from "./types";

export type Vec3 = [number, number, number];

export interface PlacedNode {
  asset: Asset;
  position: Vec3;
}

export interface MapLink {
  key: string;
  a: Vec3;
  b: Vec3;
  from: string;
  to: string;
}

const DIST_ANGLES = [0, 120, 240];
const SERVER_ANGLES = [45, 135, 225, 315];
const OUTER_ANGLES = [0, 60, 120, 180, 240, 300];

function onRing(assets: Asset[], radius: number, angles: number[]): PlacedNode[] {
  const step = 360 / Math.max(angles.length, 1);
  return assets.map((asset, index) => {
    const degrees = angles[index] ?? angles[index % angles.length] + step / 2;
    const rad = (degrees * Math.PI) / 180;
    return {
      asset,
      position: [Math.cos(rad) * radius, 0, Math.sin(rad) * radius] as Vec3,
    };
  });
}

export function placeNodes(assets: Asset[]): PlacedNode[] {
  const ordered = assets.slice().sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const namedCores = ordered.filter((asset) => asset.type === "ROUTER" && /core/i.test(`${asset.id} ${asset.name}`));
  const cores = namedCores.length > 0 ? namedCores : ordered.filter((asset) => asset.type === "ROUTER").slice(0, 2);
  const coreIds = new Set(cores.map((asset) => asset.id));
  const distribution = ordered.filter((asset) => asset.type === "ROUTER" && !coreIds.has(asset.id));
  const servers = ordered.filter((asset) => asset.type === "SERVER");
  const workstations = ordered.filter((asset) => asset.type === "WORKSTATION");
  const sensors = ordered.filter((asset) => asset.type !== "ROUTER" && asset.type !== "SERVER" && asset.type !== "WORKSTATION");
  const coreSlots: Vec3[] = [
    [-3, 0, 0],
    [3, 0, 0],
  ];
  const corePlaced = cores.map((asset, index) => ({
    asset,
    position: coreSlots[index] ?? ([3 + (index - 1) * 3, 0, 0] as Vec3),
  }));
  return [
    ...corePlaced,
    ...onRing(distribution, 8, DIST_ANGLES),
    ...onRing(servers, 16, SERVER_ANGLES),
    ...onRing(workstations, 22, OUTER_ANGLES),
    ...onRing(sensors, 22, OUTER_ANGLES.map((angle) => angle + 30)),
  ];
}

function nearest(node: PlacedNode, pool: PlacedNode[]): PlacedNode | null {
  let best: PlacedNode | null = null;
  let score = Number.POSITIVE_INFINITY;
  for (const other of pool) {
    const dx = node.position[0] - other.position[0];
    const dz = node.position[2] - other.position[2];
    const next = dx * dx + dz * dz;
    if (next < score) {
      score = next;
      best = other;
    }
  }
  return best;
}

export function topology(nodes: PlacedNode[]): MapLink[] {
  const cores = nodes.filter((node) => node.asset.type === "ROUTER" && /core/i.test(`${node.asset.id} ${node.asset.name}`));
  const coreIds = new Set(cores.map((node) => node.asset.id));
  const distribution = nodes.filter((node) => node.asset.type === "ROUTER" && !coreIds.has(node.asset.id));
  const servers = nodes.filter((node) => node.asset.type === "SERVER");
  const outer = nodes.filter((node) => node.asset.type !== "ROUTER" && node.asset.type !== "SERVER");
  const lines: MapLink[] = [];
  if (cores.length >= 2) {
    lines.push({ key: "core-link", a: cores[0].position, b: cores[1].position, from: cores[0].asset.id, to: cores[1].asset.id });
  }
  const hubs = cores.length > 0 ? cores : distribution;
  for (const node of distribution) {
    for (const core of hubs) {
      if (core.asset.id === node.asset.id) continue;
      lines.push({ key: `${node.asset.id}-${core.asset.id}`, a: node.position, b: core.position, from: node.asset.id, to: core.asset.id });
    }
  }
  const serverHubs = distribution.length > 0 ? distribution : hubs;
  for (const server of servers) {
    const hub = nearest(server, serverHubs);
    if (hub) lines.push({ key: `${server.asset.id}-${hub.asset.id}`, a: server.position, b: hub.position, from: server.asset.id, to: hub.asset.id });
  }
  for (const node of outer) {
    const hub = nearest(node, servers.length > 0 ? servers : serverHubs);
    if (hub) lines.push({ key: `${node.asset.id}-${hub.asset.id}`, a: node.position, b: hub.position, from: node.asset.id, to: hub.asset.id });
  }
  return lines;
}

export function route(lines: MapLink[], from: string, to: string): string[] {
  const next = new Map<string, string[]>();
  const join = (a: string, b: string) => {
    const list = next.get(a) ?? [];
    list.push(b);
    next.set(a, list);
  };
  lines.forEach((line) => {
    join(line.from, line.to);
    join(line.to, line.from);
  });
  const prev = new Map<string, string | null>();
  const queue = [from];
  prev.set(from, null);
  while (queue.length > 0) {
    const id = queue.shift() as string;
    if (id === to) break;
    for (const hop of next.get(id) ?? []) {
      if (prev.has(hop)) continue;
      prev.set(hop, id);
      queue.push(hop);
    }
  }
  if (!prev.has(to)) return [from, to];
  const path = [to];
  let cursor: string | null = to;
  while (cursor && cursor !== from) {
    cursor = prev.get(cursor) ?? null;
    if (cursor) path.push(cursor);
  }
  return path.reverse();
}

export function attackRoute(assets: Asset[], from: string, to: string): string[] {
  return route(topology(placeNodes(assets)), from, to);
}
