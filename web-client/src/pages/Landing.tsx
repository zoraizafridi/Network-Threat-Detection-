import { useLayoutEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import Lenis from "lenis";
import "lenis/dist/lenis.css";
import { useApp } from "../store";
import { NeuralBrainBackground } from "../components/NeuralBrainBackground";
import { NetworkHeroSection } from "../components/NetworkHeroSection";
import { ParticleBackground } from "../components/ParticleBackground";
import { useReducedMotion } from "../useReducedMotion";
import { SYSTEM_NAME } from "../brand";
import { cssToken } from "../theme";

gsap.registerPlugin(ScrollTrigger);

const MOVES = [
  { n: "01", title: "Detect", text: "Read incoming events.", icon: "detect" },
  { n: "02", title: "Score", text: "Calculate host risk.", icon: "score" },
  { n: "03", title: "Plan", text: "Select response links.", icon: "plan" },
  { n: "04", title: "Report", text: "Record the outcome.", icon: "report" },
];

function MoveIcon({ name }: { name: string }) {
  if (name === "detect") {
    return (
      <svg className="move-icon" viewBox="0 0 48 48" aria-hidden="true">
        <circle cx="24" cy="24" r="16" />
        <circle cx="24" cy="24" r="8" />
        <line x1="24" y1="8" x2="24" y2="0" />
        <line x1="24" y1="48" x2="24" y2="40" />
      </svg>
    );
  }
  if (name === "score") {
    return (
      <svg className="move-icon" viewBox="0 0 56 48" aria-hidden="true">
        <rect x="8" y="32" width="8" height="16" />
        <rect x="20" y="24" width="8" height="24" />
        <rect x="32" y="16" width="8" height="32" />
        <rect x="44" y="8" width="8" height="40" />
      </svg>
    );
  }
  if (name === "plan") {
    return (
      <svg className="move-icon" viewBox="0 0 48 48" aria-hidden="true">
        <circle cx="8" cy="8" r="4" />
        <circle cx="40" cy="8" r="4" />
        <circle cx="24" cy="40" r="4" />
        <line x1="12" y1="8" x2="36" y2="8" />
        <line x1="8" y1="12" x2="24" y2="36" />
        <line x1="40" y1="12" x2="24" y2="36" />
      </svg>
    );
  }
  return (
    <svg className="move-icon" viewBox="0 0 48 56" aria-hidden="true">
      <rect x="8" y="8" width="32" height="40" rx="2" />
      <line x1="16" y1="20" x2="32" y2="20" />
      <line x1="16" y1="28" x2="32" y2="28" />
      <line x1="16" y1="36" x2="24" y2="36" />
    </svg>
  );
}

function settleLower(stage: HTMLElement) {
  gsap.set(stage.querySelector(".process-line"), { scaleX: 1 });
  gsap.set(stage.querySelectorAll(".replica-process h3"), { color: cssToken("--text-heading", "#E8DCC4") });
  gsap.set(stage.querySelectorAll(".close-word"), { y: 0, opacity: 1 });
  gsap.set(stage.querySelectorAll(".close-net-lines path"), { strokeDashoffset: 0 });
}

export function Landing() {
  const reduced = useReducedMotion();
  const navigate = useNavigate();
  const auth = useApp((state) => state.auth);
  const root = useRef<HTMLElement>(null);
  const lenisRef = useRef<Lenis | null>(null);
  const entering = useRef(false);
  const enterTl = useRef<gsap.core.Tween | null>(null);
  const overlayRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const stage = root.current;
    if (!stage) return;
    const marks = ".nav, .badge, .heading-word, .subline-word, .action-btn";
    if (reduced) {
      gsap.set(stage.querySelectorAll(marks), { y: 0, opacity: 1 });
      settleLower(stage);
      return;
    }
    const lenis = new Lenis({ anchors: { offset: -24 } });
    lenisRef.current = lenis;
    lenis.on("scroll", ScrollTrigger.update);
    const ticker = (time: number) => lenis.raf(time * 1000);
    gsap.ticker.add(ticker);
    gsap.ticker.lagSmoothing(0);
    const intro = gsap.context(() => {
      gsap.timeline({ delay: 0.2 })
        .fromTo(".nav", { y: -12, opacity: 0 }, { y: 0, opacity: 1, duration: 0.8, ease: "power3.out" })
        .fromTo(".badge", { y: 20, opacity: 0 }, { y: 0, opacity: 1, duration: 0.8, ease: "power3.out" }, "-=0.6")
        .fromTo(
          ".heading-word",
          { y: 24, opacity: 0 },
          { y: 0, opacity: 1, duration: 0.8, stagger: 0.075, ease: "power3.out" },
          "-=0.5",
        )
        .fromTo(
          ".subline-word",
          { y: 12, opacity: 0 },
          { y: 0, opacity: 1, duration: 0.6, stagger: 0.02, ease: "power3.out" },
          "-=0.6",
        )
        .fromTo(".action-btn", { y: 20, opacity: 0 }, { y: 0, opacity: 1, duration: 0.8, ease: "power3.out" }, "-=0.4");
    }, stage);
    const lower = gsap.context(() => {
      const line = stage.querySelector(".process-line");
      const icons = stage.querySelectorAll<SVGSVGElement>(".move-icon");
      const titles = stage.querySelectorAll(".replica-process h3");
      const titleIdle = cssToken("--text-label", "#A7B8AC");
      const titleLit = cssToken("--text-heading", "#E8DCC4");
      icons.forEach((icon) => {
        icon.querySelectorAll("circle, line, rect, path").forEach((shape) => {
          if (!(shape instanceof SVGGeometryElement) || typeof shape.getTotalLength !== "function") return;
          const length = shape.getTotalLength() || 80;
          gsap.set(shape, { strokeDasharray: length, strokeDashoffset: length });
        });
      });
      gsap.set(line, { scaleX: 0, transformOrigin: "left center" });
      gsap.set(titles, { color: titleIdle });
      const draw = gsap.timeline({
        scrollTrigger: {
          trigger: ".replica-process ol",
          start: "top 80%",
          end: "bottom 60%",
          scrub: true,
        },
      });
      draw.to(line, { scaleX: 1, ease: "none", duration: 1 }, 0);
      icons.forEach((icon, index) => {
        const marks = icon.querySelectorAll("circle, line, rect, path");
        const at = index * 0.25;
        draw.to(marks, { strokeDashoffset: 0, ease: "none", duration: 0.18 }, at);
        draw.set(titles[index], { color: titleLit }, at + 0.14);
      });
      gsap.fromTo(
        ".close-word",
        { y: 40, opacity: 0 },
        {
          y: 0,
          opacity: 1,
          duration: 0.8,
          stagger: 0.08,
          ease: "power3.out",
          scrollTrigger: { trigger: ".replica-close", start: "top 75%" },
        },
      );
      const net = stage.querySelectorAll<SVGPathElement>(".close-net-lines path");
      net.forEach((path) => {
        const length = typeof path.getTotalLength === "function" ? path.getTotalLength() || 640 : 640;
        gsap.set(path, { strokeDasharray: length, strokeDashoffset: length });
      });
      gsap.to(net, {
        strokeDashoffset: 0,
        ease: "none",
        scrollTrigger: {
          trigger: ".replica-close",
          start: "top 85%",
          end: "bottom 45%",
          scrub: true,
        },
      });
      gsap.to(".close-net-traffic path", {
        strokeDashoffset: -240,
        duration: 7,
        ease: "none",
        repeat: -1,
      });
    }, stage);
    return () => {
      lower.revert();
      intro.revert();
      enterTl.current?.kill();
      gsap.ticker.remove(ticker);
      lenis.destroy();
      lenisRef.current = null;
    };
  }, [reduced]);

  function enter() {
    const go = () => navigate(auth === "in" ? "/portal" : "/roles");
    const overlay = overlayRef.current;
    if (reduced || !overlay || entering.current) {
      go();
      return;
    }
    entering.current = true;
    lenisRef.current?.stop();
    gsap.set(overlay, { y: "-100%" });
    enterTl.current = gsap.to(overlay, {
      y: "0%",
      duration: 0.6,
      ease: "power3.inOut",
      onComplete: go,
    });
  }

  function jump(id: string) {
    const target = document.getElementById(id);
    if (!target) return;
    if (lenisRef.current) lenisRef.current.scrollTo(target, { offset: -24 });
    else target.scrollIntoView();
  }

  return (
    <main className="landing" ref={root}>
      <div className="portal-wipe" ref={overlayRef} />
      <div className="landing-grain" aria-hidden="true">
        <svg>
          <filter id="landing-grain">
            <feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="2" stitchTiles="stitch" />
          </filter>
          <rect width="100%" height="100%" filter="url(#landing-grain)" />
        </svg>
      </div>

      <section className="vesper-hero">
        <div className="vesper-depth" aria-hidden="true" />
        <div className="vesper-grid" aria-hidden="true" />
        {reduced ? null : <NeuralBrainBackground />}
        {reduced ? null : <ParticleBackground reduced={false} />}
        <div className="vesper-scrim" aria-hidden="true" />
        <header className="nav">
          <p className="vesper-brand">{SYSTEM_NAME}</p>
          <nav className="nav-links" aria-label="Landing">
            {MOVES.map((move) => (
              <button key={move.title} type="button" onClick={() => jump(move.title === "Detect" ? "process-section" : move.title.toLowerCase())}>
                {move.title}
              </button>
            ))}
          </nav>
          <button type="button" className="enter-pill" onClick={enter}>Enter Portal</button>
        </header>
        <div className="vesper-center">
          <p className="badge">SECURE NETWORK ACTIVE</p>
          <h1>
            {"Detection for a live network.".split(" ").map((word, index) => (
              <span key={`${word}-${index}`} className={`word heading-word${word === "Detection" ? " is-gold" : ""}`}>{word}</span>
            ))}
          </h1>
          <p className="subline">
            {"Four detectors read every event on a simulated network. The server scores the hosts and returns the plan.".split(" ").map((word, index) => (
              <span key={`${word}-${index}`} className="word subline-word">{word}</span>
            ))}
          </p>
          <button type="button" className="action-btn" onClick={enter}>Enter portal</button>
        </div>
        <p className="vesper-foot">{"\u00A9"} 2026 {SYSTEM_NAME}.</p>
      </section>

      <section className="replica-process" id="process-section">
        <svg className="process-orbit" viewBox="0 0 200 200" aria-hidden="true">
          <circle cx="100" cy="100" r="70" />
          <circle cx="100" cy="100" r="88" />
          <ellipse cx="100" cy="100" rx="96" ry="34" />
          <ellipse cx="100" cy="100" rx="34" ry="96" />
        </svg>
        <div>
          <p className="mono">02 / Four moves</p>
          <h2>
            From the event
            <br />
            to the report.
          </h2>
        </div>
        <div className="process-track">
          <div className="process-line" />
          <ol>
            {MOVES.map((move) => (
              <li key={move.n} id={move.title.toLowerCase() === "detect" ? undefined : move.title.toLowerCase()}>
                <span className="mono">{move.n}</span>
                <MoveIcon name={move.icon} />
                <h3>{move.title}</h3>
                <p>{move.text}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="replica-inside" id="network">
        <div className="inside-copy">
          <p className="mono">03 / Inside the network</p>
          <h2>
            A real-time
            <br />
            view of your
            <br />
            network.
          </h2>
          <p>Explore the topology, inspect hosts and trace active threats across eighteen assets.</p>
          <a className="text-link" href="#process-section">Explore the network {"\u2192"}</a>
        </div>
        <NetworkHeroSection />
      </section>

      <section className="replica-close">
        <svg className="close-net" viewBox="0 0 1200 520" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
          <g className="close-net-lines">
            <path d="M120 80 H340 L560 160 L780 80 L1040 140" />
            <path d="M120 80 L180 260 L420 320 L680 280 L920 360" />
            <path d="M560 160 L420 320" />
            <path d="M560 160 L680 280" />
            <path d="M780 80 L680 280 L860 420" />
            <path d="M1040 140 L920 360 L1100 240" />
            <path d="M180 260 L260 440 L600 460 L860 420" />
            <path d="M420 320 L600 460" />
            <path d="M920 360 L860 420" />
          </g>
          <g className="close-net-traffic">
            <path d="M120 80 H340 L560 160 L780 80 L1040 140" />
            <path d="M120 80 L180 260 L420 320 L680 280 L920 360" />
            <path d="M780 80 L680 280 L860 420" />
            <path d="M180 260 L260 440 L600 460 L860 420" />
            <path d="M1040 140 L920 360 L1100 240" />
          </g>
          <g className="close-net-nodes">
            <circle cx="120" cy="80" r="4" />
            <circle cx="340" cy="80" r="3" />
            <circle cx="560" cy="160" r="4" />
            <circle cx="780" cy="80" r="3" />
            <circle cx="1040" cy="140" r="4" />
            <circle cx="180" cy="260" r="3" />
            <circle cx="420" cy="320" r="4" />
            <circle cx="680" cy="280" r="3" />
            <circle cx="920" cy="360" r="4" />
            <circle cx="1100" cy="240" r="3" />
            <circle cx="260" cy="440" r="3" />
            <circle cx="600" cy="460" r="4" />
            <circle cx="860" cy="420" r="3" />
          </g>
        </svg>
        <div className="close-copy">
          <h2>
            {"A clearer view of every connection.".split(" ").map((word, index) => (
              <span key={`${word}-${index}`} className="close-word">{word}</span>
            ))}
          </h2>
          <div>
            <p>Built for real networks. Designed for response.</p>
            <button type="button" className="close-enter" onClick={enter}>Enter portal</button>
          </div>
        </div>
      </section>

      <footer className="replica-foot">
        <p>CT-263 Object-Oriented Analysis and Design</p>
        <p>{SYSTEM_NAME}</p>
        <button type="button" onClick={enter}>Enter portal {"\u2192"}</button>
      </footer>
    </main>
  );
}
