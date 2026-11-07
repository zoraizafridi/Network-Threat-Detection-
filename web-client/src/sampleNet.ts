export type HostKind = "router" | "server" | "workstation" | "iot";

export type SampleHost = {
  id: string;
  name: string;
  ip: string;
  kind: HostKind;
  tier: 0 | 1 | 2 | 3;
};

export type SampleLink = {
  id: string;
  a: string;
  b: string;
  tier: 0 | 1 | 2 | 3;
};

export const SAMPLE_HOSTS: SampleHost[] = [
  { id: "rt-core-1", name: "Core Router 1", ip: "10.0.0.1", kind: "router", tier: 0 },
  { id: "rt-core-2", name: "Core Router 2", ip: "10.0.0.2", kind: "router", tier: 0 },
  { id: "rt-dist-1", name: "Distribution Router 1", ip: "10.0.0.3", kind: "router", tier: 0 },
  { id: "srv-web-1", name: "Web Server 1", ip: "10.0.1.10", kind: "server", tier: 1 },
  { id: "srv-web-2", name: "Web Server 2", ip: "10.0.1.11", kind: "server", tier: 1 },
  { id: "srv-db-1", name: "Database Server 1", ip: "10.0.1.20", kind: "server", tier: 1 },
  { id: "srv-auth-1", name: "Auth Server 1", ip: "10.0.1.30", kind: "server", tier: 1 },
  { id: "ws-ops-1", name: "Ops Workstation 1", ip: "10.0.2.1", kind: "workstation", tier: 2 },
  { id: "ws-ops-2", name: "Ops Workstation 2", ip: "10.0.2.2", kind: "workstation", tier: 2 },
  { id: "ws-fin-1", name: "Finance Workstation 1", ip: "10.0.2.11", kind: "workstation", tier: 2 },
  { id: "ws-fin-2", name: "Finance Workstation 2", ip: "10.0.2.12", kind: "workstation", tier: 2 },
  { id: "ws-sec-1", name: "Security Workstation 1", ip: "10.0.2.50", kind: "workstation", tier: 2 },
  { id: "ws-dev-1", name: "Dev Workstation 1", ip: "10.0.2.70", kind: "workstation", tier: 2 },
  { id: "iot-cam-1", name: "Building Camera 1", ip: "10.0.3.1", kind: "iot", tier: 3 },
  { id: "iot-cam-2", name: "Building Camera 2", ip: "10.0.3.2", kind: "iot", tier: 3 },
  { id: "iot-sensor-1", name: "Temperature Sensor 1", ip: "10.0.3.10", kind: "iot", tier: 3 },
  { id: "iot-sensor-2", name: "Humidity Sensor 1", ip: "10.0.3.11", kind: "iot", tier: 3 },
  { id: "iot-badge-1", name: "Door Badge Reader 1", ip: "10.0.3.20", kind: "iot", tier: 3 },
];

export const SAMPLE_LINKS: SampleLink[] = [
  { id: "link-r1-r2", a: "rt-core-1", b: "rt-core-2", tier: 0 },
  { id: "link-r2-r3", a: "rt-core-2", b: "rt-dist-1", tier: 0 },
  { id: "link-r3-r1", a: "rt-dist-1", b: "rt-core-1", tier: 0 },
  { id: "link-s1-r1", a: "srv-web-1", b: "rt-core-1", tier: 1 },
  { id: "link-s1-r2", a: "srv-web-1", b: "rt-core-2", tier: 1 },
  { id: "link-s2-r2", a: "srv-web-2", b: "rt-core-2", tier: 1 },
  { id: "link-s2-s1", a: "srv-web-2", b: "srv-web-1", tier: 1 },
  { id: "link-s3-r1", a: "srv-db-1", b: "rt-core-1", tier: 1 },
  { id: "link-s4-r2", a: "srv-auth-1", b: "rt-core-2", tier: 1 },
  { id: "link-w1-r3", a: "ws-ops-1", b: "rt-dist-1", tier: 2 },
  { id: "link-w2-r3", a: "ws-ops-2", b: "rt-dist-1", tier: 2 },
  { id: "link-w1-w2", a: "ws-ops-1", b: "ws-ops-2", tier: 2 },
  { id: "link-w3-r3", a: "ws-fin-1", b: "rt-dist-1", tier: 2 },
  { id: "link-w4-r3", a: "ws-fin-2", b: "rt-dist-1", tier: 2 },
  { id: "link-w5-r3", a: "ws-sec-1", b: "rt-dist-1", tier: 2 },
  { id: "link-w6-r3", a: "ws-dev-1", b: "rt-dist-1", tier: 2 },
  { id: "link-i1-r3", a: "iot-cam-1", b: "rt-dist-1", tier: 3 },
  { id: "link-i2-r3", a: "iot-cam-2", b: "rt-dist-1", tier: 3 },
  { id: "link-i3-r3", a: "iot-sensor-1", b: "rt-dist-1", tier: 3 },
  { id: "link-i4-r3", a: "iot-sensor-2", b: "rt-dist-1", tier: 3 },
  { id: "link-i5-r1", a: "iot-badge-1", b: "rt-core-1", tier: 3 },
];

const INTRO_LINKS = SAMPLE_LINKS.filter((link) => link.tier <= 2).length;

export const SIGNAL_ROUTE = ["link-w1-r3", "link-r3-r1", "link-s3-r1"];

export const HOST_POS: Record<string, [number, number, number]> = {};

const LATITUDE: Record<HostKind, number> = {
  router: 0.15,
  server: 0.72,
  workstation: -0.28,
  iot: -0.95,
};

(["router", "server", "workstation", "iot"] as HostKind[]).forEach((kind) => {
  const group = SAMPLE_HOSTS.filter((host) => host.kind === kind);
  group.forEach((host, index) => {
    const turn = (index / group.length) * Math.PI * 2 + (kind === "server" ? 0.5 : kind === "iot" ? 0.3 : 0);
    const latitude = LATITUDE[kind];
    const radius = 1.2;
    HOST_POS[host.id] = [
      Math.cos(turn) * Math.cos(latitude) * radius,
      Math.sin(latitude) * radius,
      Math.sin(turn) * Math.cos(latitude) * radius,
    ];
  });
});

export function clamp01(value: number) {
  return Math.min(1, Math.max(0, value));
}

export function linkShown(index: number, reveal: number, scroll: number) {
  const link = SAMPLE_LINKS[index];
  if (link.tier <= 2) return clamp01(reveal * INTRO_LINKS - index);
  return clamp01(scroll * (SAMPLE_LINKS.length - INTRO_LINKS + 2) - (index - INTRO_LINKS));
}

export function hostShown(tier: number, reveal: number, scroll: number) {
  if (tier <= 2) return clamp01(reveal * 1.7 - tier * 0.28);
  return clamp01(scroll * 2.4);
}

export function hopChain(source: string, target: string): string[] {
  if (source === target) return [];
  const next = new Map<string, { id: string; to: string }[]>();
  for (const link of SAMPLE_LINKS) {
    const ab = next.get(link.a) ?? [];
    ab.push({ id: link.id, to: link.b });
    next.set(link.a, ab);
    const ba = next.get(link.b) ?? [];
    ba.push({ id: link.id, to: link.a });
    next.set(link.b, ba);
  }
  const from = new Map<string, { id: string; via: string }>();
  const queue = [source];
  const seen = new Set([source]);
  while (queue.length) {
    const current = queue.shift();
    if (!current) break;
    for (const edge of next.get(current) ?? []) {
      if (seen.has(edge.to)) continue;
      seen.add(edge.to);
      from.set(edge.to, { id: edge.id, via: current });
      if (edge.to === target) {
        const ids: string[] = [];
        let node = target;
        while (node !== source) {
          const step = from.get(node);
          if (!step) return [];
          ids.push(step.id);
          node = step.via;
        }
        return ids.reverse();
      }
      queue.push(edge.to);
    }
  }
  return [];
}
