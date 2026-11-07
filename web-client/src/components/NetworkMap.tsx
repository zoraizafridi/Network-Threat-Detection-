import { Suspense, useEffect, useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { ContactShadows, Line, OrbitControls, PerspectiveCamera } from "@react-three/drei";
import * as THREE from "three";
import type { AttackPhase } from "../attackPhase";
import { AUTO_ROTATE_RESUME_MS, AUTO_ROTATE_SPEED, shouldAutoRotate } from "../autoRotate";
import { placeNodes, route, topology, type PlacedNode, type Vec3 } from "../mapPath";
import { getScenario, STAGE_NAMES, subscribeScenario } from "../scenario";
import { useApp } from "../store";
import type { Asset } from "../types";
import { useReducedMotion } from "../useReducedMotion";
import { MAP, MAP_HEMI, MAP_DIR } from "./map/MapConfig";

const NEUTRAL = MAP.nodeHealthy;
const PRIMARY = MAP.ringHealthy;
const WARN = MAP.probed;
const CRITICAL = MAP.compromised;
const ISOLATED = MAP.isolated;
const ACCENT = MAP.selection;
const LINE = MAP.link;
const SCENE_COLOR = MAP.bg;
const pointerArmed = { current: false };
const hoveredId = { current: "" };
const hoverListeners = new Set<() => void>();
const pulsesOn = { current: true };
const trailsOn = { current: true };

function subscribeHover(listener: () => void): () => void {
  hoverListeners.add(listener);
  return () => {
    hoverListeners.delete(listener);
  };
}

function hoveredSnapshot(): boolean {
  return hoveredId.current !== "";
}

function setHovered(id: string) {
  if (hoveredId.current === id) return;
  hoveredId.current = id;
  hoverListeners.forEach((listener) => listener());
}

export interface MapAttack {
  token: number | string;
  sourceId: string;
  targetId: string;
  pathIds?: string[];
  durationMs?: number;
}

function statusTint(status: string): number | null {
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
  dimmed,
  attacker,
  mark,
  onSelect,
  excluded = false,
  warned = false,
}: {
  asset: Asset;
  position: Vec3;
  selected: boolean;
  dimmed: boolean;
  attacker: boolean;
  mark?: string;
  onSelect: (id: string) => void;
  excluded?: boolean;
  warned?: boolean;
}) {
  const group = useRef<THREE.Group>(null);
  const shockMesh = useRef<THREE.Mesh>(null);
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
    const clear = () => { document.body.style.cursor = ""; };
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
          setHovered(asset.id);
          document.body.style.cursor = "pointer";
        }}
        onPointerOut={() => {
          if (hoveredId.current === asset.id) setHovered("");
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

function MapGround() {
  const material = useMemo(
    () =>
      new THREE.ShaderMaterial({
        transparent: true,
        depthWrite: false,
        uniforms: { tint: { value: new THREE.Color(MAP.groundLine) } },
        vertexShader: "varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }",
        /* One cell is one world unit, every fourth line is brighter, and both fade
           out before the rim so the plate edge never shows a hard cut. */
        fragmentShader:
          "varying vec2 vUv; uniform vec3 tint; void main(){ float r = length(vUv - 0.5) * 2.0; float radial = 1.0 - smoothstep(0.45, 0.98, r); vec2 minorCell = abs(fract(vUv * 60.0 - 0.5) - 0.5); vec2 majorCell = abs(fract(vUv * 15.0 - 0.5) - 0.5); float minor = 1.0 - smoothstep(0.0, 0.035, min(minorCell.x, minorCell.y)); float major = 1.0 - smoothstep(0.0, 0.012, min(majorCell.x, majorCell.y)); float alpha = (minor * 0.16 + major * 0.5) * radial; gl_FragColor = vec4(tint, alpha); }",
      }),
    [],
  );
  return (
    <group position={[0, -0.35, 0]}>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.02, 0]}>
        <circleGeometry args={[30, 96]} />
        <meshBasicMaterial color={MAP.ground} transparent opacity={0.95} depthWrite={false} />
      </mesh>
      <mesh rotation={[-Math.PI / 2, 0, 0]} material={material}>
        <circleGeometry args={[30, 96]} />
      </mesh>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.001, 0]}>
        <ringGeometry args={[29.5, 30, 128]} />
        <meshBasicMaterial color={MAP.groundRim} transparent opacity={0.7} side={THREE.DoubleSide} depthWrite={false} />
      </mesh>
    </group>
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
  onSlow,
  marks,
  frameKey,
  frameIds,
  shadows,
  autoRotate,
  reducedMotion,
}: {
  assets: Asset[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  attack: MapAttack | null;
  phase: AttackPhase;
  traffic: boolean;
  onSlow?: () => void;
  marks: Record<string, string>;
  frameKey: number;
  frameIds: string[];
  shadows: boolean;
  autoRotate: boolean;
  reducedMotion: boolean;
}) {
  const placed = useMemo(() => placeNodes(assets), [assets]);
  const plannerView = useApp((state) => state.plannerView);
  const lines = useMemo(() => topology(placed), [placed]);
  const at = useMemo(() => new Map(placed.map((node) => [node.asset.id, node.position])), [placed]);
  const path = useMemo(() => {
    if (!attack) return [] as string[];
    if (attack.pathIds && attack.pathIds.length > 0) return attack.pathIds;
    return route(lines, attack.sourceId, attack.targetId);
  }, [attack, lines]);
  const live = phase === "traveling" || phase === "impact";
  const involved = new Set(path);
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

  const hovering = useSyncExternalStore(subscribeHover, hoveredSnapshot, () => false);
  const [dragging, setDragging] = useState(false);
  const [idle, setIdle] = useState(true);
  const idleTimer = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (idleTimer.current !== null) window.clearTimeout(idleTimer.current);
      idleTimer.current = null;
    };
  }, []);

  const beginInput = () => {
    handsRef.current = true;
    setDragging(true);
    setIdle(false);
    if (idleTimer.current !== null) {
      window.clearTimeout(idleTimer.current);
      idleTimer.current = null;
    }
  };

  const endInput = () => {
    handsRef.current = false;
    setDragging(false);
    if (idleTimer.current !== null) window.clearTimeout(idleTimer.current);
    idleTimer.current = window.setTimeout(() => {
      idleTimer.current = null;
      setIdle(true);
    }, AUTO_ROTATE_RESUME_MS);
  };

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

  // A hovered host counts as an active focus, so the camera holds still while the pointer is on it.
  const rotating = shouldAutoRotate({
    enabled: autoRotate,
    reducedMotion,
    dragging,
    idleMs: idle ? AUTO_ROTATE_RESUME_MS : 0,
    hasSelection: Boolean(selectedId) || hovering,
    attackActive: Boolean(attack) && live,
  });

  return (
    <>
      <PerspectiveCamera makeDefault position={[8, 24, 32]} fov={42} />
      <Fit nodes={placed} hold={live} />
      <OrbitControls
        ref={controls}
        makeDefault
        enableDamping
        dampingFactor={0.1}
        minPolarAngle={0.1}
        maxPolarAngle={Math.PI / 2.1}
        autoRotate={rotating}
        autoRotateSpeed={AUTO_ROTATE_SPEED}
        onStart={beginInput}
        onEnd={endInput}
      />
      <ProjectedLabels
        nodes={placed}
        attackerId={live && path[0] ? path[0] : null}
        visible={(id) => selectedId === id || (live && involved.has(id))}
      />
      <WatchFps onSlow={onSlow} />
      <hemisphereLight color={MAP_HEMI.skyColor} groundColor={MAP_HEMI.groundColor} intensity={MAP_HEMI.intensity} />
      <directionalLight color={MAP_DIR.color} intensity={MAP_DIR.intensity} position={MAP_DIR.position} castShadow={shadows} shadow-mapSize-width={2048} shadow-mapSize-height={2048} shadow-radius={3} />
      {/* The camera sits about 75 units out, so the fog has to start past the node
          ring. A near plane of 20 used to swallow every lit mesh while the lines,
          which ignore fog, stayed visible. */}
      <fog attach="fog" args={[SCENE_COLOR, 70, 170]} />
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
      <MapGround />
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
      {placed.map((node) => (
          <HostNode
            key={node.asset.id}
            asset={node.asset}
            position={[node.position[0], node.position[1] + 1.2, node.position[2]]}
            selected={selectedId === node.asset.id}
            dimmed={Boolean(plannerView?.show && !plannerView.pairs.some((p) => p.source === node.asset.id || p.target === node.asset.id))}
            attacker={live && involved.has(node.asset.id)}
            mark={marks[node.asset.id]}
            onSelect={onSelect}
            excluded={plannerView?.excluded.includes(node.asset.id)}
            warned={plannerView?.unreachable.includes(node.asset.id)}
          />
        ))}
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
  speed?: number;
  step?: number;
  marks?: Record<string, string>;
  frameKey?: number;
  frameIds?: string[];
  shadows?: boolean;
  autoRotate?: boolean;
  onSlow?: () => void;
}

export function NetworkMap({
  assets,
  selectedId,
  onSelect,
  attack,
  phase = "idle",
  traffic = false,
  marks = {},
  frameKey = 0,
  frameIds = [],
  shadows = true,
  autoRotate = false,
  onSlow,
}: NetworkMapProps) {
  const reducedMotion = useReducedMotion();

  return (
    <Suspense fallback={null}>
      <Canvas
        camera={{ position: [8, 24, 32], fov: 42 }}
        dpr={[1, 1.5]}
        resize={{ debounce: 220 }}
        gl={{ antialias: true, alpha: false }}
        shadows={shadows ? "percentage" : false}
        onPointerMove={() => { pointerArmed.current = true; }}
        onPointerLeave={() => {
          pointerArmed.current = false;
          setHovered("");
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
          onSlow={onSlow}
          marks={marks}
          frameKey={frameKey}
          frameIds={frameIds}
          shadows={shadows}
          autoRotate={autoRotate}
          reducedMotion={reducedMotion}
        />
      </Canvas>
    </Suspense>
  );
}

let webglSupport: boolean | null = null;

function webglOk(): boolean {
  if (webglSupport !== null) {
    return webglSupport;
  }
  try {
    const canvas = document.createElement("canvas");
    const probe = canvas.getContext("webgl2") ?? canvas.getContext("webgl");
    webglSupport = Boolean(probe);
    const lose = probe?.getExtension("WEBGL_lose_context");
    lose?.loseContext();
  } catch {
    webglSupport = false;
  }
  return webglSupport;
}

function hex(value: number): string {
  return `#${value.toString(16).padStart(6, "0")}`;
}

function FlatMap({ assets, selectedId, onSelect, attack, phase }: {
  assets: Asset[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  attack?: MapAttack | null;
  phase?: AttackPhase;
}) {
  const placed = useMemo(() => placeNodes(assets), [assets]);
  const lines = useMemo(() => topology(placed), [placed]);
  const live = phase === "traveling" || phase === "impact";
  const path = attack ? (attack.pathIds ?? route(lines, attack.sourceId, attack.targetId)) : [];
  const involved = new Set(path);
  const tint = (status: string): string => {
    if (status === "COMPROMISED") return hex(MAP.compromised);
    if (status === "SUSPICIOUS") return hex(MAP.probed);
    if (status && status !== "NORMAL") return hex(MAP.isolated);
    return hex(MAP.nodeHealthy);
  };
  /* Nodes are placed in a 48 unit circle, so the SVG needs a matching viewBox.
     Without one each unit maps to a pixel and the map renders as a small cluster
     in the top left corner of a much larger element. */
  const view = useMemo(() => {
    const xs = placed.map((node) => node.position[0]);
    const zs = placed.map((node) => node.position[2]);
    /* The pad leaves room for the ground plate, which is drawn a little wider than
       the outermost ring so the plate edge is always inside the frame. */
    const pad = 13;
    const minX = (xs.length > 0 ? Math.min(...xs) : -22) + 24 - pad;
    const maxX = (xs.length > 0 ? Math.max(...xs) : 22) + 24 + pad;
    const minY = (zs.length > 0 ? -Math.max(...zs) : -22) + 24 - pad;
    const maxY = (zs.length > 0 ? -Math.min(...zs) : 22) + 24 + pad;
    const size = Math.max(maxX - minX, maxY - minY, 68);
    return { x: (minX + maxX) / 2 - size / 2, y: (minY + maxY) / 2 - size / 2, size };
  }, [placed]);
  return (
    <svg
      className="flat-map"
      viewBox={`${view.x} ${view.y} ${view.size} ${view.size}`}
      preserveAspectRatio="xMidYMid meet"
      role="group"
      aria-label="Network topology, flat view"
    >
      <defs>
        <radialGradient id="flat-plate" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#0F2218" stopOpacity="0.98" />
          <stop offset="72%" stopColor="#0B1A11" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#07100B" stopOpacity="0.55" />
        </radialGradient>
        {/* Six world units per cell keeps the grid readable without crowding the rings. */}
        <pattern id="flat-grid" width="6" height="6" patternUnits="userSpaceOnUse">
          <path className="flat-grid-line" d="M6 0H0V6" fill="none" strokeWidth="0.07" />
        </pattern>
        <marker id="flat-arrow" markerWidth="3" markerHeight="2.2" refX="2.4" refY="1.1" orient="auto">
          <polygon points="0 0, 3 1.1, 0 2.2" fill={hex(MAP.link)} />
        </marker>
      </defs>
      {/* Same idea as the 3D scene: a plate laid on top of the page background, with a
         grid and a rim, so the ground is never confused with the empty canvas. */}
      <g className="flat-ground" aria-hidden="true">
        <circle cx={24} cy={24} r={30} fill="url(#flat-plate)" />
        <circle cx={24} cy={24} r={30} fill="url(#flat-grid)" />
        <circle className="flat-ground-rim" cx={24} cy={24} r={30} />
      </g>
      <g className="flat-guides" aria-hidden="true">
        {[8, 16, 22].map((radius) => (
          <circle key={radius} cx={24} cy={24} r={radius} />
        ))}
      </g>
      {lines.map((line) => {
        const hot = involved.has(line.from) && involved.has(line.to) && live;
        return (
          <line
            key={line.key}
            x1={line.a[0] + 24} y1={24 - line.a[2]}
            x2={line.b[0] + 24} y2={24 - line.b[2]}
            stroke={hot ? hex(MAP.compromised) : hex(MAP.link)}
            strokeWidth={hot ? 0.55 : 0.22}
            strokeOpacity={hot ? 1 : 0.4}
            markerEnd={hot ? "url(#flat-arrow)" : undefined}
          />
        );
      })}
      {placed.map((node) => {
        const onPath = involved.has(node.asset.id) && live;
        const selected = selectedId === node.asset.id;
        const t = tint(node.asset.status);
        const core = node.asset.type === "ROUTER" && /core/i.test(`${node.asset.id} ${node.asset.name}`);
        const r = core ? 2.6 : (onPath || selected ? 2.1 : 1.5);
        const cx = node.position[0] + 24;
        const cy = 24 - node.position[2];
        return (
          <g
            key={node.asset.id}
            className="flat-node"
            role="button"
            tabIndex={0}
            aria-label={`${node.asset.name}, ${node.asset.status.toLowerCase()}`}
            onClick={(e) => { e.stopPropagation(); onSelect(node.asset.id); }}
            onKeyDown={(e) => {
              if (e.key !== "Enter" && e.key !== " ") return;
              e.preventDefault();
              onSelect(node.asset.id);
            }}
          >
            <title>{`${node.asset.name} (${node.asset.ip}) - ${node.asset.status}`}</title>
            <circle cx={cx} cy={cy} r={r + 0.7} fill={hex(MAP.ringHealthy)} fillOpacity={selected ? 1 : 0.35} />
            <circle className="flat-node-dot" cx={cx} cy={cy} r={r} fill={t} fillOpacity={1} />
            {selected ? <circle cx={cx} cy={cy} r={r + 1.1} fill="none" stroke={hex(MAP.selection)} strokeWidth={0.45} /> : null}
          </g>
        );
      })}
    </svg>
  );
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
  const reduced = useReducedMotion();
  // The rotation choice stays in component state only, never in storage.
  const [rotateOn, setRotateOn] = useState(true);
  const rotate = rotateOn && !reduced;
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
        {flat ? null : (
          <button
            type="button"
            className={rotate ? "on" : undefined}
            aria-pressed={rotate}
            onClick={() => setRotateOn((value) => !value)}
            disabled={reduced}
            title={reduced
              ? "Auto-rotate is off because this device asks for reduced motion."
              : "Auto-rotate the 3D map, about one turn per 100 seconds. Pauses while you drag."}
          >
            Rotate
          </button>
        )}
      </div>
      {flat ? (
        <FlatMap assets={props.assets} selectedId={props.selectedId} onSelect={props.onSelect} attack={props.attack} phase={props.phase} />
      ) : (
        <NetworkMap
          assets={props.assets}
          selectedId={props.selectedId}
          onSelect={props.onSelect}
          attack={props.attack}
          phase={props.phase}
          onImpact={props.onImpact}
          traffic={props.traffic}
          marks={props.marks}
          frameKey={props.frameKey}
          frameIds={props.frameIds}
          shadows={tier < 1}
          autoRotate={rotate}
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