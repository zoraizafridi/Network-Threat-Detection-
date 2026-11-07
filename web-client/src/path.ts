export interface PathLink {
  source: string;
  target: string;
}

export function hopPath(links: PathLink[], src: string, dst: string): string[] {
  if (!src || !dst) return [];
  if (src === dst) return [src];
  const neighbours = new Map<string, string[]>();
  const add = (from: string, to: string) => {
    const list = neighbours.get(from) ?? [];
    list.push(to);
    neighbours.set(from, list);
  };
  const ordered = links
    .filter((link) => link.source !== link.target)
    .slice()
    .sort((a, b) => {
      const left = `${a.source}|${a.target}`;
      const right = `${b.source}|${b.target}`;
      return left < right ? -1 : left > right ? 1 : 0;
    });
  for (const link of ordered) {
    add(link.source, link.target);
    add(link.target, link.source);
  }
  for (const list of neighbours.values()) {
    list.sort();
  }
  const previous = new Map<string, string>();
  const queue = [src];
  previous.set(src, "");
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index];
    if (current === dst) break;
    for (const next of neighbours.get(current) ?? []) {
      if (previous.has(next)) continue;
      previous.set(next, current);
      queue.push(next);
    }
  }
  if (!previous.has(dst)) return [];
  const path = [dst];
  let cursor = dst;
  while (cursor !== src) {
    cursor = previous.get(cursor) ?? "";
    if (!cursor) return [];
    path.push(cursor);
  }
  path.reverse();
  return path;
}

export interface PathPoint {
  x: number;
  y: number;
  z: number;
}

export function pointAlong(points: PathPoint[], t: number): PathPoint {
  if (points.length === 0) return { x: 0, y: 0, z: 0 };
  if (points.length === 1 || t <= 0) return points[0];
  if (t >= 1) return points[points.length - 1];
  const lengths: number[] = [];
  let total = 0;
  for (let i = 1; i < points.length; i += 1) {
    const span = Math.hypot(points[i].x - points[i - 1].x, points[i].z - points[i - 1].z);
    lengths.push(span);
    total += span;
  }
  if (total === 0) return points[0];
  let remain = total * t;
  for (let i = 0; i < lengths.length; i += 1) {
    if (remain > lengths[i]) {
      remain -= lengths[i];
      continue;
    }
    const u = lengths[i] === 0 ? 0 : remain / lengths[i];
    const a = points[i];
    const b = points[i + 1];
    return {
      x: a.x + (b.x - a.x) * u,
      y: a.y + (b.y - a.y) * u,
      z: a.z + (b.z - a.z) * u,
    };
  }
  return points[points.length - 1];
}
