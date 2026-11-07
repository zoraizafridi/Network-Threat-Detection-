import { useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Line } from "@react-three/drei";
import * as THREE from "three";

const SAND = "#E8DCC4";
const WIRE = "#8FA898";
const AMBER = "#D9A05B";
const RED = "#FF4B4B";
const NODE_COUNT = 12;
const HOT = 5;

type MotionRefs = {
  reduced: boolean;
  awake: boolean;
  progressRef: RefObject<number>;
  revealRef: RefObject<number>;
  departRef: RefObject<number>;
};

function place(index: number): [number, number, number] {
  const y = 1 - ((index + 0.5) / NODE_COUNT) * 2;
  const ring = Math.sqrt(Math.max(0, 1 - y * y));
  const theta = Math.PI * (1 + Math.sqrt(5)) * index;
  const radius = 3.35;
  return [Math.cos(theta) * ring * radius, y * radius * 0.92, Math.sin(theta) * ring * radius];
}

const NODES = Array.from({ length: NODE_COUNT }, (_, index) => place(index));

function Field({ reduced, awake }: MotionRefs) {
  const tilt = useRef<THREE.Group>(null);
  const spin = useRef<THREE.Group>(null);
  const signal = useRef<THREE.Mesh>(null);
  const pointer = useRef({ x: 0, y: 0 });
  const clock = useRef(0);
  const { camera, invalidate } = useThree();

  const links = useMemo(() => {
    const pairs: [[number, number, number], [number, number, number]][] = [];
    for (let index = 0; index < NODE_COUNT; index += 1) {
      pairs.push([NODES[index], NODES[(index + 1) % NODE_COUNT]]);
      pairs.push([NODES[index], NODES[(index + 4) % NODE_COUNT]]);
    }
    return pairs;
  }, []);

  useEffect(() => {
    camera.position.set(0.8, 0.55, 13.5);
    camera.lookAt(0, 0, 0);
    invalidate();
  }, [camera, invalidate]);

  useEffect(() => {
    if (reduced) return;
    const onMove = (event: PointerEvent) => {
      pointer.current.x = (event.clientX / window.innerWidth) * 2 - 1;
      pointer.current.y = (event.clientY / window.innerHeight) * 2 - 1;
    };
    window.addEventListener("pointermove", onMove);
    return () => window.removeEventListener("pointermove", onMove);
  }, [reduced]);

  useFrame((_, delta) => {
    if (!reduced && awake && !document.hidden) {
      clock.current += delta;
      const t = clock.current;
      camera.position.set(
        0.8 + Math.sin(t * 0.15) * 0.28,
        0.55 + Math.cos(t * 0.12) * 0.18,
        13.5 + Math.sin(t * 0.1) * 0.2,
      );
      camera.lookAt(0, 0, 0);
    }
    if (tilt.current && !reduced) {
      const targetX = pointer.current.y * -0.12;
      const targetY = pointer.current.x * 0.18;
      tilt.current.rotation.x += (targetX - tilt.current.rotation.x) * 0.06;
      tilt.current.rotation.y += (targetY - tilt.current.rotation.y) * 0.06;
    }
    if (signal.current) {
      const ride = links[0];
      const along = reduced ? 0 : (Math.sin(clock.current * 0.7) + 1) / 2;
      const from = ride[0];
      const to = ride[1];
      signal.current.position.set(
        from[0] + (to[0] - from[0]) * along,
        from[1] + (to[1] - from[1]) * along,
        from[2] + (to[2] - from[2]) * along,
      );
    }
    if (reduced || !awake || document.hidden || !spin.current) return;
    spin.current.rotation.y += delta * 0.07;
    spin.current.rotation.z += delta * 0.012;
  });

  return (
    <>
      <fog attach="fog" args={["#091710", 10, 25]} />
      <ambientLight intensity={0.5} />
      <directionalLight position={[-6, 8, 4]} intensity={1.15} color="#E8DCC4" />
      <group ref={tilt}>
      <group ref={spin} rotation={[0.2, 0.4, 0]}>
      <group scale={0.7}>
      <mesh>
        <sphereGeometry args={[3.4, 12, 8]} />
        <meshStandardMaterial wireframe color={WIRE} roughness={0.8} metalness={0.2} emissive={WIRE} emissiveIntensity={0.22} toneMapped={false} />
      </mesh>
      {[
        [1.15, 0.15, 0.35, 4.15],
        [0.35, 1.1, 0.2, 4.7],
        [0.8, 0.4, 1.05, 3.7],
      ].map(([rx, ry, rz, radius]) => (
        <mesh key={radius} rotation={[rx, ry, rz]}>
          <ringGeometry args={[radius, radius + 0.015, 80]} />
          <meshBasicMaterial color={WIRE} transparent opacity={0.55} side={THREE.DoubleSide} toneMapped={false} />
        </mesh>
      ))}
      {links.map((points, index) => (
        <Line key={index} points={points} color={index % 7 === 0 ? AMBER : WIRE} lineWidth={1} transparent opacity={0.8} />
      ))}
      <mesh ref={signal}>
        <sphereGeometry args={[0.09, 12, 12]} />
        <meshBasicMaterial color={AMBER} toneMapped={false} />
      </mesh>
      {NODES.map((position, index) => {
        const hot = index === HOT;
        const color = hot ? RED : SAND;
        return (
          <group key={index} position={position}>
            {index % 3 === 0 ? (
              <mesh>
                <cylinderGeometry args={[0.12, 0.12, 0.1, 12]} />
                <meshStandardMaterial color={color} roughness={0.8} metalness={0.2} emissive={color} emissiveIntensity={0.18} toneMapped={false} />
              </mesh>
            ) : (
              <group>
                <mesh position={[0, 0.08, 0]}>
                  <boxGeometry args={[0.2, 0.11, 0.16]} />
                  <meshStandardMaterial color={color} roughness={0.8} metalness={0.2} emissive={color} emissiveIntensity={0.18} toneMapped={false} />
                </mesh>
                <mesh position={[0, 0.26, 0]}>
                  <boxGeometry args={[0.2, 0.1, 0.16]} />
                  <meshStandardMaterial color={color} roughness={0.8} metalness={0.2} emissive={color} emissiveIntensity={0.18} toneMapped={false} />
                </mesh>
              </group>
            )}
            {hot ? (
              <>
                <mesh rotation={[Math.PI / 2, 0, 0]}>
                  <ringGeometry args={[0.42, 0.45, 32]} />
                  <meshBasicMaterial color={RED} side={THREE.DoubleSide} toneMapped={false} />
                </mesh>
                <mesh>
                  <sphereGeometry args={[0.55, 16, 16]} />
                  <meshBasicMaterial color={RED} transparent opacity={0.18} toneMapped={false} />
                </mesh>
                <pointLight color={RED} intensity={2} distance={5} />
              </>
            ) : null}
          </group>
        );
      })}
      </group>
      </group>
      </group>
    </>
  );
}

export function HeroNetwork(props: MotionRefs) {
  const [hidden, setHidden] = useState(false);
  useEffect(() => {
    const onVis = () => setHidden(document.hidden);
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, []);
  const quiet = props.reduced || !props.awake || hidden;
  return (
    <div className="net-canvas" aria-hidden="true">
      <Canvas
        dpr={[1, 2]}
        frameloop={quiet ? "demand" : "always"}
        camera={{ position: [0.8, 0.55, 13.5], fov: 35, near: 0.1, far: 40 }}
        gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
        onCreated={({ gl }) => {
          gl.toneMapping = THREE.NoToneMapping;
          gl.setClearColor(0x000000, 0);
        }}
      >
        <Field {...props} />
      </Canvas>
    </div>
  );
}
