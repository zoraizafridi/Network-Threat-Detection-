import { useMemo, useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import * as THREE from "three";

const SIGNALS = 3;
const SAND = "#E8DCC4";
const MUTED = "#B9C4B3";

function keyOf(x: number, y: number, z: number) {
  return `${Math.round(x * 1000)}:${Math.round(y * 1000)}:${Math.round(z * 1000)}`;
}

function wire(detail: number, radius: number) {
  const shape = new THREE.IcosahedronGeometry(radius, detail);
  const position = shape.attributes.position;
  const index = shape.index;
  const seenPoints = new Set<string>();
  const points: number[] = [];
  const seenEdges = new Set<string>();
  const pairs: number[] = [];
  const addPoint = (x: number, y: number, z: number) => {
    const key = keyOf(x, y, z);
    if (seenPoints.has(key)) return;
    seenPoints.add(key);
    points.push(x, y, z);
  };
  const add = (a: number, b: number) => {
    const ax = position.getX(a);
    const ay = position.getY(a);
    const az = position.getZ(a);
    const bx = position.getX(b);
    const by = position.getY(b);
    const bz = position.getZ(b);
    addPoint(ax, ay, az);
    addPoint(bx, by, bz);
    const ka = keyOf(ax, ay, az);
    const kb = keyOf(bx, by, bz);
    const key = ka < kb ? `${ka}|${kb}` : `${kb}|${ka}`;
    if (seenEdges.has(key)) return;
    seenEdges.add(key);
    pairs.push(ax, ay, az, bx, by, bz);
  };
  const tri = (a: number, b: number, c: number) => {
    add(a, b);
    add(b, c);
    add(c, a);
  };
  if (index) {
    for (let i = 0; i < index.count; i += 3) tri(index.getX(i), index.getX(i + 1), index.getX(i + 2));
  } else {
    for (let i = 0; i < position.count; i += 3) tri(i, i + 1, i + 2);
  }
  shape.dispose();
  return { points: new Float32Array(points), lines: new Float32Array(pairs) };
}

function signalTracks(lines: Float32Array): Float32Array {
  const segments = Math.floor(lines.length / 6);
  const ranked: { index: number; length: number }[] = [];
  for (let i = 0; i < segments; i += 1) {
    const o = i * 6;
    const length = Math.hypot(lines[o] - lines[o + 3], lines[o + 1] - lines[o + 4], lines[o + 2] - lines[o + 5]);
    ranked.push({ index: i, length });
  }
  ranked.sort((a, b) => b.length - a.length);
  const tracks = new Float32Array(SIGNALS * 6);
  const step = Math.max(1, Math.floor(ranked.length / (SIGNALS + 1)));
  for (let i = 0; i < SIGNALS; i += 1) {
    const edge = ranked[Math.min(ranked.length - 1, step * (i + 1))];
    tracks.set(lines.subarray(edge.index * 6, edge.index * 6 + 6), i * 6);
  }
  return tracks;
}

function placeSignals(attr: THREE.BufferAttribute, tracks: Float32Array, amount: number) {
  for (let i = 0; i < SIGNALS; i += 1) {
    const u = Math.min(1, Math.max(0, amount * SIGNALS - i));
    const o = i * 6;
    attr.setXYZ(
      i,
      tracks[o] + (tracks[o + 3] - tracks[o]) * u,
      tracks[o + 1] + (tracks[o + 4] - tracks[o + 1]) * u,
      tracks[o + 2] + (tracks[o + 5] - tracks[o + 2]) * u,
    );
  }
  attr.needsUpdate = true;
}

function SphereBody({
  reduced,
  progressRef,
}: {
  reduced: boolean;
  progressRef: { current: number };
}) {
  const group = useRef<THREE.Group>(null);
  const signal = useRef<THREE.Points>(null);
  const outer = useMemo(() => wire(2, 1.2), []);
  const inner = useMemo(() => wire(1, 0.58), []);
  const tracks = useMemo(() => signalTracks(outer.lines), [outer]);
  const signalStart = useMemo(() => {
    const start = new Float32Array(SIGNALS * 3);
    const attr = new THREE.BufferAttribute(start, 3);
    placeSignals(attr, tracks, reduced ? 1 : 0);
    return start;
  }, [reduced, tracks]);

  useFrame((_, delta) => {
    const node = group.current;
    if (!node || document.hidden) return;
    if (!reduced) node.rotation.y += delta * 0.08;
    const cloud = signal.current;
    if (!cloud || reduced) return;
    const attr = cloud.geometry.getAttribute("position") as THREE.BufferAttribute;
    placeSignals(attr, tracks, Math.min(1, progressRef.current / 0.35));
  });

  return (
    <group ref={group}>
      <lineSegments>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[inner.lines, 3]} />
        </bufferGeometry>
        <lineBasicMaterial color={MUTED} depthTest={false} />
      </lineSegments>
      <lineSegments>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[outer.lines, 3]} />
        </bufferGeometry>
        <lineBasicMaterial color={SAND} depthTest={false} />
      </lineSegments>
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[outer.points, 3]} />
        </bufferGeometry>
        <pointsMaterial color={SAND} size={0.035} sizeAttenuation depthTest={false} />
      </points>
      <points ref={signal}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[signalStart, 3]} />
        </bufferGeometry>
        <pointsMaterial color={SAND} size={0.07} sizeAttenuation depthTest={false} />
      </points>
    </group>
  );
}

export function ParticleSphere({
  reduced,
  progressRef,
}: {
  reduced: boolean;
  progressRef: { current: number };
}) {
  return (
    <Canvas
      camera={{ position: [0, 0, 4.7], fov: 32 }}
      dpr={[1, 1.5]}
      gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
      frameloop={reduced ? "demand" : "always"}
      style={{ width: "100%", height: "100%" }}
      onCreated={({ gl }) => {
        gl.toneMapping = THREE.NoToneMapping;
        gl.setClearColor(0x000000, 0);
      }}
    >
      <SphereBody reduced={reduced} progressRef={progressRef} />
    </Canvas>
  );
}
