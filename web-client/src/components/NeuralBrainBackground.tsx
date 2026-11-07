import { useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import type { Mesh } from "three";

function TorusKnot() {
  const meshRef = useRef<Mesh>(null);

  useFrame((_state, delta) => {
    const mesh = meshRef.current;
    if (!mesh) return;
    mesh.rotation.x += delta * 0.1;
    mesh.rotation.y += delta * 0.15;
  });

  return (
    <mesh ref={meshRef}>
      <torusKnotGeometry args={[2.5, 0.6, 128, 64, 2, 3]} />
      <meshBasicMaterial color="#D9A05B" wireframe transparent opacity={0.1} />
    </mesh>
  );
}

export function NeuralBrainBackground() {
  return (
    <div className="vesper-orb" aria-hidden="true">
      <Canvas
        camera={{ position: [0, 0, 10], fov: 45 }}
        dpr={[1, 1.5]}
        gl={{ alpha: true, antialias: true }}
        onCreated={({ gl }) => gl.setClearColor(0x000000, 0)}
      >
        <TorusKnot />
      </Canvas>
    </div>
  );
}
