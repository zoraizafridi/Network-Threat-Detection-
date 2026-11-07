import { Suspense, useEffect, useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { ContactShadows, Line, OrbitControls, PerspectiveCamera } from "@react-three/drei";
import * as THREE from "three";
import type { AttackPhase } from "../attackPhase";
import { placeNodes, route, topology, type PlacedNode, type MapLink, type Vec3 } from "../mapPath";
import { getScenario, STAGE_NAMES, subscribeScenario } from "../scenario";
import { useApp } from "../store";
import type { Asset } from "../types";
import { useReducedMotion } from "../useReducedMotion";
import { MAP, MAP_HEMI, MAP_DIR } from "./map/MapConfig";

const NEUTRAL = MAP.nodeHealthy;
const PRIMARY = MAP.ringHealthy;
const OK = MAP.probed;
const WARN = MAP.probed;
const CRITICAL = MAP.compromised;
const ISOLATED = MAP.isolated;
const ACCENT = MAP.selection;
const LINE = MAP.link;
const SCENE_COLOR = MAP.bg;
const pointerArmed = { current: false };
const hoveredId = { current: "" };
const pulsesOn = { current: true };
const TEXT = "#e9e4d4";

export interface MapAttack {
  token: number | string;
  sourceId: string;
  targetId: string;
  pathIds?: string[];
  durationMs?: number;
}

type Placed = PlacedNode;
type LinkLine = MapLink;

function lift(position: Vec3): Vec3 {
  return [position[0], 1.2, position[2]];
}

function statusTint(status: string): string | null {
  if (status === "COMPROMISED") return CRITICAL;
  if (status === "SUSPICIOUS") return WARN;
  if (status && status !== "NORMAL") return ISOLATED;
  return null;
}

function Body({ type }: { type: string }) {
  if (type === "ROUTER") {
    return (
      <group position={[0, 0.7, 0]}>
        <mesh position={[0, 0, 0]}><cylinderGeometry args={[0.72, 0.84, 0.42, 20]} />        <meshStandardMaterial color={NEUTRAL} roughness={0.6} metalness={0.1} /></mesh>
        <mesh position={[0, 0.55, 0]}><cylinderGeometry args={[0.4, 0.4, 0.5, 12]} /><meshStandardMaterial color={NEUTRAL} roughness={0.6} metalness={0.1} /></mesh>
      </group>
    );
  }
  if (type === "SERVER") {
    return (
      <group position={[0, 0.15, 0]}>
        {[0, 0.42, 0.84].map((y) => (
          <mesh key={y} position={[0, y, 0]}>
            <boxGeometry args={[1.8, 0.42, 1.15]} />
            <meshStandardMaterial color={NEUTRAL} roughness={0.6} metalness={0.1} />
          </mesh>
        ))}
      </group>
    );
  }
  if (type === "WORKSTATION") {
    return (
      <group position={[0, 0.2, 0]}>
        <mesh position={[0, 0.7, 0]}><boxGeometry args={[1.45, 0.95, 0.12]} /><meshStandardMaterial color={NEUTRAL} roughness={0.6} metalness={0.1} /></mesh>
        <mesh position={[0, 0.16, 0]}><boxGeometry args={[0.55, 0.22, 0.55]} /><meshStandardMaterial color={NEUTRAL} roughness={0.6} metalness={0.1} /></mesh>
      </group>
    );
  }
  return (
    <group position={[0, 0.35, 0]}>
      <mesh><boxGeometry args={[0.7, 0.7, 0.7]} /><meshStandardMaterial color={NEUTRAL} roughness={0.6} metalness={0.1} /></mesh>
      <mesh position={[0, 0.48, 0.22]}><sphereGeometry args={[0.22, 16, 16]} /><meshStandardMaterial color={NEUTRAL} roughness={0.6} metalness={0.1} /></mesh>
    </group>
  );
}

function HostNode({
  asset,
  position,
  selected,
  onPath,
  dimmed,
  showLabel,
  labelNudge,
  attacker,
  mark,
  onSelect,
  excluded = false,
  warned = false,
}: {
  asset: Asset;
  position: Vec3;
  selected: boolean;
  onPath: boolean;
  dimmed: boolean;
  showLabel: boolean;
  labelNudge: number;
  attacker: boolean;
  mark?: string;
  onSelect: (id: string) => void;
  excluded?: boolean;
  warned?: boolean;
}) {
  const group = useRef<THREE.Group>(null);
  const shockMesh = useRef<THREE.Mesh>(null);
  const [hovered, setHovered] = useState(false);
  const tint = statusTint(mark || asset.status);
  const ring = tint ?? PRIMARY;
  const body = tint ?? NEUTRAL;
  const core = asset.type === "ROUTER" && /core/i.test(`${asset.id} ${asset.name}`);

  const bump = useRef(0);
  const bumpVel = useRef(0);
  const seen = useRef(mark);
  const shock = useRef(0);
  const lastTick = useRef(0);

  useEffect(() => {
    const clear = () => setHovered(false);
    window.addEventListener("fs-map-leave", clear);
    return () => {
      window.removeEventListener("fs-map-leave", clear);
      document.body.style.cursor = "";
    };
  }, []);

  useFrame((state) => {
    const node = group.current;
    if (!node) return;
    if (seen.current !== mark) {
      seen.current = mark;
      bump.current = 0.18;
      bumpVel.current = 0;
      shock.current = 1;
    }
    const now = state.clock.elapsedTime;
    const dt = lastTick.current === 0 ? 0.016 : Math.min(0.032, now - lastTick.current);
    lastTick.current = now;
    const acc = -260 * bump.current - 18 * bumpVel.current;
    bumpVel.current += acc * dt;
    bump.current += bumpVel.current * dt;
    if (Math.abs(bump.current) < 0.004 && Math.abs(bumpVel.current) < 0.004) {
      bump.current = 0;
      bumpVel.current = 0;
    }
    shock.current = Math.max(0, shock.current - dt / 0.7);
    if (shockMesh.current) {
      const wave = 1 + (1 - shock.current) * 2.4;
      shockMesh.current.scale.setScalar(wave);
      shockMesh.current.visible = shock.current > 0;
      const material = shockMesh.current.material as THREE.MeshBasicMaterial;
      if (material) material.opacity = shock.current;
    }
    const base = core ? 1.35 : 1;
    node.scale.setScalar(base * (1 + bump.current));
    const pulse = tint === CRITICAL && pulsesOn.current ? 0.4 + 0.5 * (0.5 + 0.5 * Math.sin(state.clock.elapsedTime * (Math.PI * 2) / 1.6)) : 0;
    node.traverse((object) => {
      const mesh = object as THREE.Mesh;
      if (!mesh.isMesh) return;
      const material = mesh.material as THREE.MeshStandardMaterial;
      if (!material?.emissive || !material.color) return;
      const isolated = tint === ISOLATED;
      material.transparent = dimmed || isolated;
      material.opacity = dimmed ? 0.28 : isolated ? 0.55 : 1;
      material.color.set(body);
      material.emissive.set(pulse > 0 ? CRITICAL : "#000000");
      material.emissiveIntensity = pulse;
    });
  });

  return (
    <group ref={group} position={position}>
      <group
        onClick={(event) => {
          event.stopPropagation();
          onSelect(asset.id);
        }}
        onPointerOver={(event) => {
          event.stopPropagation();
          if (!pointerArmed.current) return;
          hoveredId.current = asset.id;
          setHovered(true);
          document.body.style.cursor = "pointer";
        }}
        onPointerOut={() => {
          if (hoveredId.current === asset.id) hoveredId.current = "";
          setHovered(false);
          document.body.style.cursor = "";
        }}
      >
        <Body type={asset.type} />
      </group>
      {ring ? (
        <mesh position={[0, 0.04, 0]} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[1.15, 1.32, 40]} />
          <meshBasicMaterial color={ring} transparent opacity={dimmed ? 0.25 : 0.9} side={THREE.DoubleSide} />
        </mesh>
      ) : (
        <mesh position={[0, 0.04, 0]} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[1.15, 1.24, 40]} />
          <meshBasicMaterial color={NEUTRAL} transparent opacity={dimmed ? 0.08 : 0.28} side={THREE.DoubleSide} />
        </mesh>
      )}
      {selected ? (
        <mesh position={[0, 0.05, 0]} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[1.48, 1.66, 48]} />
          <meshBasicMaterial color={ACCENT} transparent opacity={0.95} side={THREE.DoubleSide} />
        </mesh>
      ) : null}
      {attacker ? (
        <mesh position={[0, 0.06, 0]} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[1.4, 1.55, 40]} />
          <meshBasicMaterial color={LINE} transparent opacity={0.95} side={THREE.DoubleSide} />
        </mesh>
      ) : null}
      {excluded ? <Line points={ringPoints(1.7)} color={ISOLATED} dashed dashSize={0.18} gapSize={0.12} lineWidth={2} /> : null}
      {warned ? <Line points={ringPoints(1.9)} color={WARN} lineWidth={2} /> : null}
      <mesh ref={shockMesh} visible={false} position={[0, 0.08, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[1.1, 1.2, 40]} />
        <meshBasicMaterial color={CRITICAL} transparent opacity={0} side={THREE.DoubleSide} />
      </mesh>
    </group>
  );
}

function HopPulse({
  points,
  paused,
  duration,
}: {
  points: Vec3[];
  paused: boolean;
  duration: number;
}) {
  const mesh = useRef<THREE.Mesh>(null);
  const started = useRef<number | null>(null);
  const held = useRef<number | null>(null);
  const lost = useRef(0);
  useFrame((state) => {
    const node = mesh.current;
    if (!node || points.length < 2) return;
    if (started.current === null) started.current = state.clock.elapsedTime;
    if (paused) {
      if (held.current === null) held.current = state.clock.elapsedTime;
      return;
    }
    if (held.current !== null && started.current !== null) {
      lost.current += state.clock.elapsedTime - held.current;
      held.current = null;
    }
    const hops = points.length - 1;
    const span = Math.max(0.2, duration);
    const t = Math.min(1, (state.clock.elapsedTime - started.current - lost.current) / span);
    const scaled = t * hops;
    const index = Math.min(hops - 1, Math.floor(scaled));
    const local = scaled - index;
    const from = points[index];
    const to = points[Math.min(hops, index + 1)];
    node.position.set(
      THREE.MathUtils.lerp(from[0], to[0], local),
      THREE.MathUtils.lerp(from[1], to[1], local),
      THREE.MathUtils.lerp(from[2], to[2], local),
    );
  });
  return (
    <mesh ref={mesh} position={points[0]}>
      <sphereGeometry args={[0.28, 16, 16]} />
      <meshStandardMaterial color={TEXT} emissive={CRITICAL} emissiveIntensity={1.2} />
    </mesh>
  );
}

function Drift({ a, b, offset }: { a: Vec3; b: Vec3; offset: number }) {
  const mesh = useRef<THREE.Mesh>(null);
  useFrame((state) => {
    const node = mesh.current;
    if (!node) return;
    const t = (state.clock.elapsedTime * 0.12 + offset) % 1;
    node.position.set(
      THREE.MathUtils.lerp(a[0], b[0], t),
      0.35,
      THREE.MathUtils.lerp(a[2], b[2], t),
    );
  });
  return (
    <mesh ref={mesh} position={[a[0], 0.35, a[2]]}>
      <sphereGeometry args={[0.12, 8, 8]} />
      <meshBasicMaterial color={LINE} transparent opacity={0.5} />
    </mesh>
  );
}

const omega = 9;
const springScratch = new THREE.Vector3();
function springStep(current: THREE.Vector3, goal: THREE.Vector3, velocity: THREE.Vector3, dt: number) {
  springScratch.copy(goal).sub(current).multiplyScalar(omega * omega);
  springScratch.addScaledVector(velocity, -2 * omega);
  velocity.addScaledVector(springScratch, dt);
  current.addScaledVector(velocity, dt);
}

function FadeGrid() {
  const material = useMemo(
    () =>
      new THREE.ShaderMaterial({
        transparent: true,
        depthWrite: false,
        uniforms: { tint: { value: new THREE.Color(MAP.grid) } },
        vertexShader: "varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }",
        fragmentShader:
          "varying vec2 vUv; uniform vec3 tint; void main(){ vec2 g = abs(fract(vUv * 22.0 - 0.5) - 0.5); float line = 1.0 - smoothstep(0.0, 0.06, min(g.x, g.y)); float radial = 1.0 - smoothstep(0.05, 0.75, length(vUv - 0.5)); gl_FragColor = vec4(tint, line * radial * 0.30); }",
      }),
    [],
  );
  return (
    <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.35, 0]} material={material}>
      <planeGeometry args={[90, 90]} />
    </mesh>
  );
}

function ringPoints(radius: number): Vec3[] {
  const points: Vec3[] = [];
  for (let index = 0; index <= 28; index += 1) {
    const angle = (index / 28) * Math.PI * 2;
    points.push([Math.cos(angle) * radius, 0.09, Math.sin(angle) * radius]);
  }
  return points;
}

function curveOf(a: Vec3, b: Vec3): THREE.QuadraticBezierCurve3 {
  const span = Math.hypot(b[0] - a[0], b[2] - a[2]);
  const mid = new THREE.Vector3((a[0] + b[0]) / 2, 0.2 + span * 0.08, (a[2] + b[2]) / 2);
  return new THREE.QuadraticBezierCurve3(new THREE.Vector3(a[0], 0.2, a[2]), mid, new THREE.Vector3(b[0], 0.2, b[2]));
}

function easeInOut(t: number): number {
  return t < 0.5 ? 2 * t * t : 1 - ((-2 * t + 2) ** 2) / 2;
}

const trailsOn = { current: true };

function HopFlight({
  from,
  to,
  duration,
  paused,
  thick,
}: {
  from: Vec3;
  to: Vec3;
  duration: number;
  paused: boolean;
  thick: boolean;
}) {
  const head = useRef<THREE.Mesh>(null);
  const arrow = useRef<THREE.Mesh>(null);
  const dots = useRef<THREE.Mesh[]>([]);
  const started = useRef<number | null>(null);
  const held = useRef<number | null>(null);
  const lost = useRef(0);
  const reduced = useReducedMotion();
  const curve = useMemo(() => curveOf(from, to), [from, to]);
  useFrame((state) => {
    if (started.current === null) started.current = state.clock.elapsedTime;
    if (paused) {
      if (held.current === null) held.current = state.clock.elapsedTime;
      return;
    }
    if (held.current !== null && started.current !== null) {
      lost.current += state.clock.elapsedTime - held.current;
      held.current = null;
    }
    const raw = reduced ? 1 : Math.min(1, (state.clock.elapsedTime - started.current - lost.current) / Math.max(0.2, duration));
    const t = easeInOut(raw);
    const point = curve.getPoint(t);
    const ahead = curve.getPoint(Math.min(1, t + 0.04));
    if (head.current) head.current.position.copy(point);
    if (arrow.current) {
      const mark = curve.getPoint(0.7);
      const tangent = curve.getPoint(0.74);
      arrow.current.position.copy(mark);
      arrow.current.lookAt(tangent);
    }
    if (!trailsOn.current || reduced) return;
    dots.current.forEach((dot, index) => {
      if (!dot) return;
      const sample = curve.getPoint(Math.max(0, t - (index + 1) * 0.035));
      dot.position.copy(sample);
    });
  });
  const drawn = curve.getPoints(32);
  return (
    <group>
      <Line points={drawn} color={CRITICAL} lineWidth={thick ? 5 : 2.5} transparent opacity={thick ? 0.95 : 0.85} />
      <mesh ref={head}>
        <sphereGeometry args={[0.16, 12, 12]} />
        <meshBasicMaterial color={CRITICAL} />
      </mesh>
      {Array.from({ length: 6 }, (_, index) => (
        <mesh key={index} ref={(node) => { dots.current[index] = node as THREE.Mesh; }}>
          <sphereGeometry args={[0.08, 8, 8]} />
          <meshBasicMaterial color={CRITICAL} transparent opacity={0.7 - index * 0.1} />
        </mesh>
      ))}
      <mesh ref={arrow}>
        <coneGeometry args={[0.16, 0.42, 8]} />
        <meshBasicMaterial color={CRITICAL} />
      </mesh>
    </group>
  );
}

function ProjectedLabels({
  nodes,
  visible,
  attackerId,
}: {
  nodes: PlacedNode[];
  visible: (id: string) => boolean;
  attackerId: string | null;
}) {
  const { camera, gl, size } = useThree();
  const els = useRef<Map<string, HTMLDivElement>>(new Map());
  const projected = new THREE.Vector3();
  useFrame(() => {
    const parent = gl.domElement.parentElement;
    if (!parent || size.width < 1 || size.height < 1) return;
    let root = parent.querySelector<HTMLDivElement>(".map-labels");
    if (!root) {
      root = document.createElement("div");
      root.className = "map-labels";
      parent.appendChild(root);
    }
    const placed: { id: string; el: HTMLDivElement; x: number; y: number }[] = [];
    const seen = new Set<string>();
    for (const node of nodes) {
      seen.add(node.asset.id);
      let el = els.current.get(node.asset.id);
      if (!el) {
        el = document.createElement("div");
        el.className = "map-label";
        els.current.set(node.asset.id, el);
        root.appendChild(el);
      }
      const attacker = attackerId === node.asset.id;
      el.textContent = attacker ? `${node.asset.name} · Attacker` : node.asset.name;
      const show = visible(node.asset.id) || hoveredId.current === node.asset.id || attacker;
      projected.set(node.position[0], node.position[1] + 2.1, node.position[2]).project(camera);
      if (!show || projected.z > 1) {
        el.style.display = "none";
        continue;
      }
      const x = (projected.x * 0.5 + 0.5) * size.width;
      const y = (-projected.y * 0.5 + 0.5) * size.height;
      el.style.display = "block";
      placed.push({ id: node.asset.id, el, x, y });
    }
    placed.sort((a, b) => a.y - b.y || a.x - b.x);
    const used: { x: number; y: number }[] = [];
    for (const item of placed) {
      let y = item.y;
      for (const other of used) {
        if (Math.abs(other.x - item.x) < 96 && Math.abs(other.y - y) < 22) y = other.y - 22;
      }
      const x = Math.min(size.width - 8, Math.max(8, item.x));
      y = Math.min(size.height - 8, Math.max(8, y));
      used.push({ x, y });
      item.el.style.transform = `translate(-50%, -100%) translate(${x}px, ${y}px)`;
    }
    for (const [id, el] of els.current) {
      if (!seen.has(id)) {
        el.remove();
        els.current.delete(id);
      }
    }
  });
  return null;
}

function fitDistance(radius: number, width: number, height: number): number {
  const vFov = (42 * Math.PI) / 180;
  const aspect = width / Math.max(1, height);
  const padded = radius * 1.15;
  const distV = padded / Math.sin(vFov / 2);
  const hFov = 2 * Math.atan(Math.tan(vFov / 2) * aspect);
  return Math.max(distV, padded / Math.sin(hFov / 2));
}

function Fit({ nodes, hold }: { nodes: PlacedNode[]; hold: boolean }) {
  const { camera, size } = useThree();
  useLayoutEffect(() => {
    if (hold || size.width < 1 || size.height < 1 || nodes.length === 0) return;
    const box = new THREE.Box3();
    nodes.forEach((node) => box.expandByPoint(new THREE.Vector3(node.position[0], node.position[1], node.position[2])));
    const sphere = box.getBoundingSphere(new THREE.Sphere());
    const dist = fitDistance(Math.max(sphere.radius, 1), size.width, size.height);
    camera.position.set(sphere.center.x + dist * 0.22, sphere.center.y + dist * 0.55, sphere.center.z + dist * 0.78);
    camera.lookAt(sphere.center);
    if ("fov" in camera) {
      camera.fov = 42;
      camera.updateProjectionMatrix();
    }
  }, [camera, hold, nodes, size.width, size.height]);
  return null;
}

function WatchFps({ onSlow }: { onSlow?: () => void }) {
  const sample = useRef({ frames: 0, start: 0 });
  useFrame((state) => {
    if (!onSlow || document.hidden) return;
    if (sample.current.start === 0) sample.current.start = state.clock.elapsedTime;
    sample.current.frames += 1;
    const span = state.clock.elapsedTime - sample.current.start;
    if (span < 2) return;
    if (sample.current.frames / span < 1000 / 24) onSlow();
    sample.current.frames = 0;
    sample.current.start = state.clock.elapsedTime;
  });
  return null;
}

function Scene({
  assets,
  selectedId,
  onSelect,
  attack,
  phase,
  traffic,
  paused,
  onSlow,
  marks,
  frameKey,
  frameIds,
  shadows,
}: {
  assets: Asset[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  attack: MapAttack | null;
  phase: AttackPhase;
  traffic: boolean;
  paused: boolean;
  onSlow?: () => void;
  marks: Record<string, string>;
  frameKey: number;
  frameIds: string[];
  shadows: boolean;
}) {
  const placed = useMemo(() => placeNodes(assets), [assets]);
  const plannerView = useApp((state) => state.plannerView);
  const lines = useMemo(() => topology(placed), [placed]);
  const at = useMemo(() => new Map(placed.map((node) => [node.asset.id, node.position])), [placed]);
  const radius = useMemo(() => {
    let max = 8;
    placed.forEach((node) => {
      max = Math.max(max, Math.hypot(node.position[0], node.position[2]));
    });
    return max;
  }, [placed]);
  const path = useMemo(() => {
    if (!attack) return [] as string[];
    if (attack.pathIds && attack.pathIds.length > 0) return attack.pathIds;
    return route(lines, attack.sourceId, attack.targetId);
  }, [attack, lines]);
  const segment = attack ? [at.get(attack.sourceId), at.get(attack.targetId)].filter((point): point is Vec3 => Boolean(point)).map(lift) : [];
  const live = phase === "traveling" || phase === "impact";
  const involved = new Set(path);
  const [handsOn, setHandsOn] = useState(false);
  const controls = useRef<any>(null);
  const camera = useThree((state) => state.camera);
  const viewSize = useThree((state) => state.size);
  const camVel = useRef(new THREE.Vector3());
  const tgtVel = useRef(new THREE.Vector3());
  const desired = useRef<{ pos: THREE.Vector3; target: THREE.Vector3 } | null>(null);
  const frameLock = useRef(0);
  const idleUntil = useRef(0);
  const applied = useRef(0);
  const handsRef = useRef(false);
  const pending = useRef<{ key: number; ids: string[] } | null>(null);
  const idsRef = useRef(frameIds);
  idsRef.current = frameIds;

  useEffect(() => {
    pending.current = { key: frameKey, ids: idsRef.current.slice() };
  }, [frameKey]);

  useFrame(() => {
    const ctrl = controls.current;
    const now = performance.now();
    if (!ctrl || handsRef.current || now < idleUntil.current) return;
    const waiting = pending.current;
    if (waiting && waiting.key !== applied.current && now >= frameLock.current) {
      const ids = waiting.ids.filter((id) => at.has(id));
      if (ids.length === 0) {
        const boxAll = new THREE.Box3();
        placed.forEach((node) => boxAll.expandByPoint(new THREE.Vector3(node.position[0], node.position[1], node.position[2])));
        const sphere = boxAll.getBoundingSphere(new THREE.Sphere());
        const dist = fitDistance(Math.max(sphere.radius, 1), Math.max(viewSize.width, 1), Math.max(viewSize.height, 1));
        desired.current = {
          pos: new THREE.Vector3(sphere.center.x + dist * 0.22, sphere.center.y + dist * 0.55, sphere.center.z + dist * 0.78),
          target: sphere.center,
        };
      } else {
        const box = new THREE.Box3();
        ids.forEach((id) => {
          const point = at.get(id);
          if (point) box.expandByPoint(new THREE.Vector3(point[0], 1, point[2]));
        });
        const center = box.getCenter(new THREE.Vector3());
        const dist = Math.max(24, box.getSize(new THREE.Vector3()).length() * 2.4);
        desired.current = { pos: new THREE.Vector3(center.x + dist * 0.3, dist * 0.72, center.z + dist), target: center };
      }
      applied.current = waiting.key;
      frameLock.current = now + 4000;
      pending.current = null;
    }
    const goal = desired.current;
    if (!goal) return;
    const dt = 0.016;
    springStep(camera.position, goal.pos, camVel.current, dt);
    springStep(ctrl.target, goal.target, tgtVel.current, dt);
    if (camera.position.distanceTo(goal.pos) < 0.2 && camVel.current.length() < 0.2) {
      desired.current = null;
      camVel.current.set(0, 0, 0);
      tgtVel.current.set(0, 0, 0);
    }
  });

  let labelSlot = 0;

  return (
    <>
      <PerspectiveCamera makeDefault position={[8, 24, 32]} fov={42} />
      <Fit nodes={placed} hold={live} />
      <ProjectedLabels
        nodes={placed}
        attackerId={live && path[0] ? path[0] : null}
        visible={(id) => selectedId === id || (live && involved.has(id))}
      />
      <WatchFps onSlow={onSlow} />
      <hemisphereLight color={MAP_HEMI.skyColor} groundColor={MAP_HEMI.groundColor} intensity={MAP_HEMI.intensity} />
      <directionalLight color={MAP_DIR.color} intensity={MAP_DIR.intensity} position={MAP_DIR.position} castShadow={shadows} shadow-mapSize-width={2048} shadow-mapSize-height={2048} shadow-radius={3} />
      <fog attach="fog" args={[SCENE_COLOR, 20, 80]} />
      <ContactShadows position={[0, -0.34, 0]} opacity={0.4} scale={48} blur={2.5} far={10} color="#000000" />
      <mesh
        rotation={[-Math.PI / 2, 0, 0]}
        position={[0, -0.5, 0]}
        onClick={(event) => {
          event.stopPropagation();
          onSelect("");
        }}
      >
        <planeGeometry args={[240, 240]} />
        <meshBasicMaterial color={SCENE_COLOR} transparent opacity={0} depthWrite={false} />
      </mesh>
      <FadeGrid />
      {lines.map((line) => {
        const hot = involved.has(line.from) && involved.has(line.to) && live;
        const faded = (live && !hot) || Boolean(plannerView?.show);
        return (
          <Line
            key={line.key}
            points={[line.a, line.b]}
            color={hot ? MAP.compromised : MAP.link}
            lineWidth={hot ? 4 : 1.25}
            transparent
            opacity={hot ? 0.95 : faded ? 0.25 : 0.35}
          />
        );
      })}
      {plannerView?.show
        ? plannerView.pairs.map((pair) => {
            const start = at.get(pair.source);
            const end = at.get(pair.target);
            if (!start || !end) return null;
            const hovered = plannerView.hover === pair.id;
            return <Line key={pair.id} points={[start, end]} color={LINE} lineWidth={hovered ? 6 : 4} transparent opacity={hovered ? 1 : 0.9} />;
          })
        : null}
      {traffic && !live
        ? lines.map((line, index) => <Drift key={`drift-${line.key}`} a={line.a} b={line.b} offset={index * 0.17} />)
        : null}
      {placed.map((node) => {
        const onPath = involved.has(node.asset.id) && live;
        const visible = Boolean(selectedId === node.asset.id || onPath);
        const nudge = visible ? (labelSlot++ % 3 - 1) * 14 : 0;
        return (
          <HostNode
            key={node.asset.id}
            asset={node.asset}
            position={[node.position[0], node.position[1] + 1.2, node.position[2]]}
            selected={selectedId === node.asset.id}
            onPath={onPath}
            dimmed={Boolean(plannerView?.show && !plannerView.pairs.some((p) => p.source === node.asset.id || p.target === node.asset.id))}
            showLabel={visible}
            labelNudge={nudge}
            attacker={live && involved.has(node.asset.id)}
            mark={marks[node.asset.id]}
            onSelect={onSelect}
            excluded={plannerView?.excluded.includes(node.asset.id)}
            warned={plannerView?.unreachable.includes(node.asset.id)}
          />
        );
      })}
    </>
  );
}

interface NetworkMapProps {
  assets: Asset[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  attack?: MapAttack | null;
  phase?: AttackPhase;
  onImpact?: () => void;
  traffic?: boolean;
  paused?: boolean;
  speed?: number;
  step?: number;
  marks?: Record<string, string>;
  frameKey?: number;
  frameIds?: string[];
  shadows?: boolean;
  onSlow?: () => void;
}

export function NetworkMap({
  assets,
  selectedId,
  onSelect,
  attack,
  phase = "idle",
  traffic = false,
  paused = false,
  marks = {},
  frameKey = 0,
  frameIds = [],
  shadows = true,
  onSlow,
}: NetworkMapProps) {
  return (
    <Suspense fallback={null}>
      <Canvas
        camera={{ position: [8, 24, 32], fov: 42 }}
        dpr={[1, 1.5]}
        resize={{ debounce: 220 }}
        gl={{ antialias: true, alpha: false }}
        shadows={shadows}
        onPointerMove={() => { pointerArmed.current = true; }}
        onPointerLeave={() => {
          pointerArmed.current = false;
          hoveredId.current = "";
          window.dispatchEvent(new Event("fs-map-leave"));
        }}
        onCreated={({ gl, camera, raycaster }) => {
          gl.setClearColor(MAP.bg, 1);
          raycaster.setFromCamera(new THREE.Vector2(-10, -10), camera);
        }}
        onPointerMissed={() => onSelect("")}
      >
        <Scene
          assets={assets}
          selectedId={selectedId}
          onSelect={onSelect}
          attack={attack ?? null}
          phase={phase}
          traffic={traffic}
          paused={paused}
          onSlow={onSlow}
          marks={marks}
          frameKey={frameKey}
          frameIds={frameIds}
          shadows={shadows}
        />
      </Canvas>
    </Suspense>
  );
}

function webglOk(): boolean {
  try {
    const canvas = document.createElement("canvas");
    return Boolean(canvas.getContext("webgl2") || canvas.getContext("webgl"));
  } catch {

function FlatMap({ assets, selectedId, onSelect, attack, phase, marks }: {
  assets: Asset[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  attack?: MapAttack | null;
  phase?: AttackPhase;
  marks?: Record<string, string>;
}) {
  const placed = useMemo(() => placeNodes(assets), [assets]);
  const lines = useMemo(() => topology(placed), [placed]);
  const live = phase === "traveling" || phase === "impact";
  const path = attack ? (attack.pathIds ?? route(lines, attack.sourceId, attack.targetId)) : [];
  const involved = new Set(path);
  const tint = (status: string): string => {
    if (status === "COMPROMISED") return MAP.compromised.toString(16).padStart(6, "0");
    if (status === "SUSPICIOUS") return MAP.probed.toString(16).padStart(6, "0");
    if (status && status !== "NORMAL") return MAP.isolated.toString(16).padStart(6, "0");
    return MAP.nodeHealthy.toString(16).padStart(6, "0");
  };
  return (
    <svg className="flat-map" width="100%" height="100%" style={{ background: "#07100b" }}>
      <defs>
        <marker id="arrow" markerWidth="10" markerHeight="7" refX="8" refY="3.5" orient="auto">
          <polygon points="0 0, 10 3.5, 0 7" fill={MAP.link.toString(16).padStart(6, "0")} />
        </marker>
      </defs>
      {lines.map((line) => {
        const hot = involved.has(line.from) && involved.has(line.to) && live;
        return (
          <line
            key={line.key}
            x1={line.a[0] + 24} y1={24 - line.a[2]}
            x2={line.b[0] + 24} y2={24 - line.b[2]}
            stroke={hot ? MAP.compromised.toString(16).padStart(6, "0") : MAP.link.toString(16).padStart(6, "0")}
            strokeWidth={hot ? 3 : 1}
            strokeOpacity={hot ? 1 : 0.35}
            markerEnd={hot ? "url(#arrow)" : undefined}
          />
        );
      })}
      {placed.map((node) => {
        const onPath = involved.has(node.asset.id) && live;
        const selected = selectedId === node.asset.id;
        const t = tint(node.asset.status);
        const core = node.asset.type === "ROUTER" && /core/i.test(`${node.asset.id} ${node.asset.name}`);
        const r = core ? 9 : (onPath || selected ? 7 : 5);
        return (
          <g key={node.asset.id} onClick={(e) => { e.stopPropagation(); onSelect(node.asset.id); }}>
            <circle cx={node.position[0] + 24} cy={24 - node.position[2]} r={r + 2} fill={MAP.ringHealthy.toString(16).padStart(6, "0")} fillOpacity={selected ? 1 : 0.35} />
            <circle cx={node.position[0] + 24} cy={24 - node.position[2]} r={r} fill={t} fillOpacity={1} />
            {selected ? <circle cx={node.position[0] + 24} cy={24 - node.position[2]} r={r + 4} fill="none" stroke={MAP.selection.toString(16).padStart(6, "0")} strokeWidth={2} /> : null}
          </g>
        );
      })}
    </svg>
  );
}

    return false;
  }
}

export function NetworkStage(props: {
  assets: Asset[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  attack?: MapAttack | null;
  phase?: AttackPhase;
  onImpact?: () => void;
  traffic?: boolean;
  paused?: boolean;
  speed?: number;
  step?: number;
  marks?: Record<string, string>;
  frameKey?: number;
  frameIds?: string[];
}) {
  const [mode, setMode] = useState<"3d" | "2d">(webglOk() ? "3d" : "2d");
  const [tier, setTier] = useState(0);
  const flat = mode === "2d";
  const scenario = useSyncExternalStore(subscribeScenario, getScenario);
  const running = scenario.phase === "run" || (scenario.phase === "paused" && scenario.stage >= 0 && scenario.stage < 4);
  const names = scenario.path.map((id) => props.assets.find((asset) => asset.id === id)?.name ?? id).join(" -> ");
  const caption = running && scenario.stage >= 0 && scenario.stage < 4
    ? `Stage ${scenario.stage + 1} of 4, ${STAGE_NAMES[scenario.stage]}: ${names}`
    : "";
  return (
    <div className="topo-stage">
      <div className="topo-toggle">
        <button type="button" className={!flat ? "on" : undefined} onClick={() => { pulsesOn.current = true; trailsOn.current = true; setTier(0); setMode("3d"); }} disabled={!webglOk()}>3D</button>
        <button type="button" className={flat ? "on" : undefined} onClick={() => setMode("2d")}>2D</button>
      </div>
      {flat ? (
        <FlatMap assets={props.assets} selectedId={props.selectedId} onSelect={props.onSelect} attack={props.attack} phase={props.phase} marks={props.marks} />
      ) : (
        <NetworkMap
          {...props}
          shadows={tier < 1}
          onSlow={() => setTier((level) => {
            const next = level + 1;
            if (next >= 2) {
              pulsesOn.current = false;
              trailsOn.current = false;
            }
            if (next >= 3) setMode("2d");
            return next;
          })}
        />
      )}
      {caption ? <p className="map-caption">{caption}</p> : null}
      {tier >= 3 ? <p className="map-caption">Frame time stayed high. Showing the flat map.</p> : null}
    </div>
  );
}