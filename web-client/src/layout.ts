export interface LayoutInputNode {
  id: string;
  name: string;
}

export interface LayoutInputLink {
  source: string;
  target: string;
}

export interface LabelBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface PlacedNode {
  id: string;
  name: string;
  x: number;
  y: number;
  z: number;
  label: LabelBox;
}

const LABEL_SCALE = 36;

export function hashSeed(ids: string[]): number {
  let hash = 2166136261;
  const text = ids.slice().sort().join("|");
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function mulberry32(seed: number): () => number {
  let value = seed >>> 0;
  return () => {
    value |= 0;
    value = (value + 0x6d2b79f5) | 0;
    let t = Math.imul(value ^ (value >>> 15), 1 | value);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function intersects(a: LabelBox, b: LabelBox): boolean {
  return a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;
}

function labelFor(name: string, x: number, z: number): LabelBox {
  const w = Math.max(48, name.length * 7);
  const h = 16;
  return { x: x * LABEL_SCALE - w / 2, y: z * LABEL_SCALE - h - 10, w, h };
}

function separateLabels(nodes: PlacedNode[]): void {
  const shift = (index: number, dx: number, dy: number) => {
    const label = nodes[index].label;
    nodes[index].label = { ...label, x: label.x + dx, y: label.y + dy };
  };
  for (let pass = 0; pass < 100; pass += 1) {
    let moved = false;
    for (let i = 0; i < nodes.length; i += 1) {
      for (let j = 0; j < i; j += 1) {
        if (!intersects(nodes[i].label, nodes[j].label)) continue;
        shift(i, 0, -8);
        moved = true;
      }
    }
    if (!moved) return;
  }
  for (let pass = 0; pass < 100; pass += 1) {
    let moved = false;
    for (let i = 0; i < nodes.length; i += 1) {
      for (let j = 0; j < i; j += 1) {
        if (!intersects(nodes[i].label, nodes[j].label)) continue;
        shift(i, nodes[j].label.w + 4, 0);
        moved = true;
      }
    }
    if (!moved) return;
  }
}

export function layoutNetwork(assets: LayoutInputNode[], links: LayoutInputLink[]): PlacedNode[] {
  const nodes = assets.slice().sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const random = mulberry32(hashSeed(nodes.map((node) => node.id)));
  const pos = new Map<string, { x: number; y: number; z: number }>();
  nodes.forEach((node, index) => {
    const angle = (index / Math.max(nodes.length, 1)) * Math.PI * 2;
    const radius = nodes.length > 8 ? 16 : 8;
    pos.set(node.id, {
      x: Math.cos(angle) * radius + (random() - 0.5) * 0.2,
      y: 0,
      z: Math.sin(angle) * radius + (random() - 0.5) * 0.2,
    });
  });
  const known = new Set(nodes.map((node) => node.id));
  const edges = links
    .filter((link) => known.has(link.source) && known.has(link.target) && link.source !== link.target)
    .slice()
    .sort((a, b) => {
      const left = `${a.source}|${a.target}`;
      const right = `${b.source}|${b.target}`;
      return left < right ? -1 : left > right ? 1 : 0;
    });
  for (let step = 0; step < 120; step += 1) {
    const force = new Map<string, { x: number; z: number }>();
    for (const node of nodes) force.set(node.id, { x: 0, z: 0 });
    for (let i = 0; i < nodes.length; i += 1) {
      for (let j = i + 1; j < nodes.length; j += 1) {
        const a = pos.get(nodes[i].id)!;
        const b = pos.get(nodes[j].id)!;
        let dx = a.x - b.x;
        let dz = a.z - b.z;
        const dist = Math.hypot(dx, dz) || 0.01;
        const push = 6 / (dist * dist);
        dx /= dist;
        dz /= dist;
        const fi = force.get(nodes[i].id)!;
        const fj = force.get(nodes[j].id)!;
        fi.x += dx * push;
        fi.z += dz * push;
        fj.x -= dx * push;
        fj.z -= dz * push;
      }
    }
    for (const link of edges) {
      const a = pos.get(link.source)!;
      const b = pos.get(link.target)!;
      const dx = b.x - a.x;
      const dz = b.z - a.z;
      force.get(link.source)!.x += dx * 0.006;
      force.get(link.source)!.z += dz * 0.006;
      force.get(link.target)!.x -= dx * 0.006;
      force.get(link.target)!.z -= dz * 0.006;
    }
    for (const node of nodes) {
      const point = pos.get(node.id)!;
      const f = force.get(node.id)!;
      f.x += -point.x * 0.008;
      f.z += -point.z * 0.008;
      point.x += Math.max(-0.4, Math.min(0.4, f.x));
      point.z += Math.max(-0.4, Math.min(0.4, f.z));
    }
  }
  const placed = nodes.map((node) => {
    const point = pos.get(node.id)!;
    return {
      id: node.id,
      name: node.name,
      x: point.x,
      y: point.y,
      z: point.z,
      label: labelFor(node.name, point.x, point.z),
    };
  });
  separateLabels(placed);
  return placed;
}

export function labelWorld(label: LabelBox): { x: number; z: number } {
  return {
    x: (label.x + label.w / 2) / LABEL_SCALE,
    z: (label.y + label.h + 10) / LABEL_SCALE,
  };
}

export function labelsOverlap(nodes: PlacedNode[]): boolean {
  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      if (intersects(nodes[i].label, nodes[j].label)) return true;
    }
  }
  return false;
}
