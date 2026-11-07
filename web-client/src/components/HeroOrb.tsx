import { Canvas } from "@react-three/fiber";
import { MeshDistortMaterial, Sphere } from "@react-three/drei";

export function HeroOrb({ reduced }: { reduced: boolean }) {
  return (
    <div className="vesper-orb" aria-hidden="true">
      <Canvas
        camera={{ position: [0, 0, 8], fov: 40 }}
        dpr={[1, 1.5]}
        gl={{ alpha: true, antialias: true }}
        onCreated={({ gl }) => gl.setClearColor(0x000000, 0)}
      >
        <ambientLight intensity={1.2} />
        <Sphere args={[2.8, 32, 32]}>
          <meshBasicMaterial color="#050A07" />
        </Sphere>
        <Sphere args={[3, 64, 64]}>
          <MeshDistortMaterial
            color="#D9A05B"
            wireframe
            transparent
            opacity={0.15}
            distort={0.5}
            speed={reduced ? 0 : 2}
          />
        </Sphere>
      </Canvas>
    </div>
  );
}
