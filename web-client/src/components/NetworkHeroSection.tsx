import { useLayoutEffect, useRef, useState, type MouseEvent } from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { useReducedMotion } from "../useReducedMotion";

gsap.registerPlugin(ScrollTrigger);

const TABS = ["Topology", "Alerts", "Incidents", "Planner", "Reports"] as const;
type Tab = (typeof TABS)[number];

const PLACEHOLDER: Record<Exclude<Tab, "Topology">, string> = {
  Alerts: "Alerts view coming soon in the portal.",
  Incidents: "Incidents view coming soon in the portal.",
  Planner: "Planner view coming soon in the portal.",
  Reports: "Reports view coming soon in the portal.",
};

const CENTER = { x: 200, y: 200 };
const HOSTS = [
  { x: 200, y: 70 },
  { x: 291.9, y: 108.1 },
  { x: 330, y: 200 },
  { x: 291.9, y: 291.9 },
  { x: 200, y: 330 },
  { x: 108.1, y: 291.9 },
  { x: 70, y: 200 },
  { x: 108.1, y: 108.1 },
];

const LEGEND = [
  { label: "Normal 12", color: "#4ADE80" },
  { label: "Suspicious 3", color: "#FB923C" },
  { label: "Compromised 1", color: "#FF4B4B" },
  { label: "Offline 2", color: "#64748B" },
];

const SERVER = "M-14 -11 H14 V11 H-14 Z M-7 -4 H7 V6 H-7 Z";
const HOST_NAMES = ["rt-core-1", "rt-core-2", "rt-dist-1", "srv-web-2", "srv-db-1", "srv-auth-1", "ws-ops-1", "iot-cam-1"];

export function NetworkHeroSection() {
  const reduced = useReducedMotion();
  const [activeTab, setActiveTab] = useState<Tab>("Topology");
  const sectionRef = useRef<HTMLDivElement>(null);
  const tiltRef = useRef<HTMLDivElement>(null);
  const linesRef = useRef<SVGLineElement[]>([]);
  const coreRef = useRef<SVGGElement>(null);
  const moveFrame = useRef(0);

  useLayoutEffect(() => {
    const section = sectionRef.current;
    const core = coreRef.current;
    const lines = linesRef.current.filter(Boolean);
    if (activeTab !== "Topology" || !section || !core || lines.length === 0) return;
    if (reduced) {
      gsap.set(lines, { strokeDashoffset: 0 });
      gsap.set(core, { scale: 1, opacity: 1 });
      return;
    }
    const ctx = gsap.context(() => {
      gsap.set(lines, { strokeDashoffset: 100 });
      gsap.to(lines, {
        strokeDashoffset: 0,
        duration: 1.1,
        stagger: 0.05,
        ease: "power3.out",
        scrollTrigger: {
          trigger: section,
          start: "top 75%",
          once: true,
        },
        onComplete: () => {
          gsap.to(core, {
            scale: 1.1,
            opacity: 0.7,
            duration: 0.9,
            yoyo: true,
            repeat: -1,
            ease: "power3.inOut",
            transformOrigin: "center center",
          });
        },
      });
      const traffic = section.querySelectorAll(".traffic");
      gsap.to(traffic, {
        strokeDashoffset: -100,
        duration: 3.2,
        ease: "none",
        repeat: -1,
        stagger: 0.28,
      });
      const spark = section.querySelector(".network-hero-spark polyline");
      if (spark instanceof SVGGeometryElement && typeof spark.getTotalLength === "function") {
        const length = spark.getTotalLength() || 240;
        gsap.set(spark, { strokeDasharray: length, strokeDashoffset: length });
        gsap.to(spark, {
          strokeDashoffset: 0,
          duration: 2.4,
          ease: "power2.inOut",
          repeat: -1,
          yoyo: true,
        });
      }
    }, section);
    return () => ctx.revert();
  }, [reduced, activeTab]);

  function tilt(event: MouseEvent<HTMLDivElement>) {
    if (reduced) return;
    const plane = tiltRef.current;
    const bounds = event.currentTarget.getBoundingClientRect();
    const x = event.clientX;
    const y = event.clientY;
    if (moveFrame.current) return;
    moveFrame.current = window.requestAnimationFrame(() => {
      moveFrame.current = 0;
      if (!plane) return;
      const px = (x - bounds.left) / bounds.width - 0.5;
      const py = (y - bounds.top) / bounds.height - 0.5;
      gsap.to(plane, {
        rotateX: -py * 8,
        rotateY: px * 10,
        duration: 0.45,
        ease: "power3.out",
        overwrite: "auto",
      });
    });
  }

  function level() {
    if (moveFrame.current) {
      window.cancelAnimationFrame(moveFrame.current);
      moveFrame.current = 0;
    }
    if (!tiltRef.current) return;
    gsap.to(tiltRef.current, { rotateX: 0, rotateY: 0, duration: 0.6, ease: "power3.out", overwrite: "auto" });
  }

  return (
    <div
      className="network-hero"
      ref={sectionRef}
      aria-label="Network topology"
      onMouseMove={tilt}
      onMouseLeave={level}
    >
      <div className="network-tilt">
      <div className="network-tilt-plane" ref={tiltRef}>
      <div className="network-hero-panel">
        <div className="network-hero-tabs" role="tablist" aria-label="Console views">
          {TABS.map((tab) => {
            const active = tab === activeTab;
            return (
              <button
                key={tab}
                type="button"
                role="tab"
                aria-selected={active}
                className={active ? "on" : undefined}
                onClick={() => setActiveTab(tab)}
              >
                {tab}
              </button>
            );
          })}
        </div>
        {activeTab === "Topology" ? (
        <div className="network-hero-body">
          <ul className="network-hero-legend">
            {LEGEND.map((item) => (
              <li key={item.label}>
                <i style={{ background: item.color }} />
                {item.label}
              </li>
            ))}
          </ul>
          <div className="network-hero-graph">
            <svg viewBox="0 0 400 400" role="img" aria-label="Eight hosts linked to one compromised center">
              {HOSTS.map((host, index) => (
                <line
                  key={`${host.x}-${host.y}`}
                  className="spine"
                  ref={(node) => {
                    if (node) linesRef.current[index] = node;
                  }}
                  x1={CENTER.x}
                  y1={CENTER.y}
                  x2={host.x}
                  y2={host.y}
                  pathLength={100}
                />
              ))}
              {HOSTS.map((host, index) => (
                <line
                  key={`traffic-${host.x}`}
                  className="traffic"
                  x1={CENTER.x}
                  y1={CENTER.y}
                  x2={host.x}
                  y2={host.y}
                  pathLength={100}
                  style={{ animationDelay: `${index * 0.28}s` }}
                />
              ))}
              {HOSTS.map((host, index) => (
                <g key={`host-${host.x}-${host.y}`} className="node" transform={`translate(${host.x} ${host.y})`}>
                  <title>{HOST_NAMES[index]}</title>
                  <path d={SERVER} />
                  <circle className="node-glow halo" r="7" />
                  <circle className="node-glow" r="2.4" />
                </g>
              ))}
              <g className="node" transform={`translate(${CENTER.x} ${CENTER.y})`}>
                <title>web-server-1, compromised</title>
                <g ref={coreRef} className="network-hero-core">
                  <path d={SERVER} />
                  <circle className="node-glow halo hot" r="9" />
                  <circle className="node-glow hot" r="2.8" />
                </g>
              </g>
            </svg>
          </div>
          <aside className="network-hero-host">
            <p>Selected host</p>
            <h3>web-server-1</h3>
            <dl>
              <div><dt>IP</dt><dd>10.0.1.20</dd></div>
              <div><dt>Uptime</dt><dd>14d 2h</dd></div>
              <div><dt>Risk</dt><dd>72/100</dd></div>
              <div><dt>Status</dt><dd className="status"><i />Suspicious</dd></div>
            </dl>
            <svg className="network-hero-spark" viewBox="0 0 220 48" aria-hidden="true">
              <polyline pathLength={240} points="0,36 18,34 32,22 48,28 64,16 82,24 98,12 116,20 134,8 152,18 170,10 188,16 204,6 220,14" />
            </svg>
          </aside>
        </div>
        ) : (
          <p className="network-hero-note">{PLACEHOLDER[activeTab]}</p>
        )}
      </div>
      </div>
      </div>
    </div>
  );
}
