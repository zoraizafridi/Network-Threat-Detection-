import { useEffect, useRef } from "react";

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  alpha: number;
}

export function ParticleBackground({ reduced }: { reduced: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || reduced) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let w = 0;
    let h = 0;
    let animationFrameId = 0;

    function resize() {
      const node = canvasRef.current;
      if (!node) return;
      const rect = node.getBoundingClientRect();
      w = node.width = Math.max(1, Math.floor(rect.width));
      h = node.height = Math.max(1, Math.floor(rect.height));
    }
    window.addEventListener("resize", resize);
    resize();

    const particles: Particle[] = [];
    for (let i = 0; i < 60; i += 1) {
      particles.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        radius: Math.random() * 1.5 + 0.5,
        alpha: Math.random() * 0.5 + 0.1,
      });
    }

    let mouseX = w / 2;
    let mouseY = h / 2;
    const handleMouseMove = (event: MouseEvent) => {
      const node = canvasRef.current;
      if (!node) return;
      const rect = node.getBoundingClientRect();
      mouseX = event.clientX - rect.left;
      mouseY = event.clientY - rect.top;
    };
    window.addEventListener("mousemove", handleMouseMove);

    function animate() {
      const node = canvasRef.current;
      const context = node?.getContext("2d");
      if (!node || !context) return;
      context.clearRect(0, 0, w, h);
      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = w;
        if (p.x > w) p.x = 0;
        if (p.y < 0) p.y = h;
        if (p.y > h) p.y = 0;

        const dx = mouseX - p.x;
        const dy = mouseY - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 150 && dist > 0) {
          p.x -= (dx / dist) * 1.2;
          p.y -= (dy / dist) * 1.2;
        }

        context.beginPath();
        context.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        context.fillStyle = `rgba(183, 243, 107, ${p.alpha})`;
        context.fill();
      });
      animationFrameId = requestAnimationFrame(animate);
    }
    animate();

    return () => {
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", handleMouseMove);
      cancelAnimationFrame(animationFrameId);
    };
  }, [reduced]);

  return <canvas id="bg-canvas" ref={canvasRef} aria-hidden="true" />;
}
