import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { gsap } from "gsap";
import { layoutNetwork } from "../layout";
import { cameraPose, fitPose, screenForPath } from "../scene";
import { useApp } from "../store";
import { useReducedMotion } from "../useReducedMotion";
import { useSyncExternalStore } from "react";
import { NetworkMap } from "./NetworkMap";
import { getScenario, subscribeScenario } from "../scenario";

export function SceneHost() {
  const location = useLocation();
  const reduced = useReducedMotion();
  const assets = useApp((state) => state.assets);
  const links = useApp((state) => state.links);
  const selectedId = useApp((state) => state.selectedId);
  const setSelectedId = useApp((state) => state.setSelectedId);
  const scenario = useSyncExternalStore(subscribeScenario, getScenario);
  const edgePulse = useApp((state) => state.edgePulse);
  const screen = screenForPath(location.pathname);
  const placed = useMemo(
    () => layoutNetwork(assets, links),
    [assets.map((asset) => asset.id).join("|"), links.map((link) => `${link.source}|${link.target}`).join("|")],
  );
  const fit = useMemo(() => fitPose(placed.map((node) => ({ x: node.x, z: node.z }))), [placed]);
  const focusId = screen === "attack" || screen === "alerts" || screen === "overview" || screen === "portal" ? selectedId : null;
  const focusNode = placed.find((node) => node.id === focusId) ?? null;
  const pose = cameraPose(
    screen,
    fit,
    focusNode ? { x: focusNode.x, y: focusNode.y, z: focusNode.z } : null,
  );
  const dim = useRef<HTMLDivElement>(null);
  const edge = useRef<HTMLDivElement>(null);
  const root = useRef<HTMLDivElement>(null);
  const [live, setLive] = useState(false);
  const scenarioLive = scenario.phase === "run" || (scenario.phase === "paused" && scenario.stage >= 0 && scenario.stage <= 3);
  const flight = scenarioLive && scenario.segmentFrom && scenario.segmentTo
    ? {
        token: `${scenario.token}-${scenario.stage}-${scenario.hop}`,
        sourceId: scenario.segmentFrom,
        targetId: scenario.segmentTo,
        pathIds: scenario.path,
        durationMs: scenario.segmentMs,
      }
    : null;

  useEffect(() => {
    const el = root.current;
    if (!el) return;
    let shown = false;
    const place = () => {
      const slot = document.querySelector("[data-map-slot]");
      const rect = slot?.getBoundingClientRect();
      const next = Boolean(rect && rect.width > 8 && rect.height > 8);
      if (next && rect) {
        el.style.left = `${rect.left}px`;
        el.style.top = `${rect.top}px`;
        el.style.width = `${rect.width}px`;
        el.style.height = `${rect.height}px`;
      }
      if (next !== shown) {
        shown = next;
        setLive(next);
      }
      el.dataset.live = next ? "yes" : "no";
    };
    place();
    gsap.ticker.add(place);
    window.addEventListener("resize", place);
    return () => {
      gsap.ticker.remove(place);
      window.removeEventListener("resize", place);
    };
  }, [location.pathname]);

  useEffect(() => {
    const el = edge.current;
    if (!el || !edgePulse || reduced) return;
    const tween = gsap.fromTo(el, { opacity: 1 }, { opacity: 0, duration: 0.2, ease: "power3.out" });
    return () => tween.kill();
  }, [edgePulse, reduced]);

  useEffect(() => {
    const el = dim.current;
    if (!el) return;
    if (reduced) {
      gsap.set(el, { opacity: pose.dim });
      return;
    }
    const tween = gsap.to(el, { opacity: pose.dim, duration: 0.3, ease: "power3.out" });
    return () => tween.kill();
  }, [pose.dim, reduced]);

  return (
    <div ref={root} className="scene-root" data-testid="scene-root" data-live="no">
      {live ? (
        <NetworkMap
          assets={assets}
          selectedId={selectedId}
          onSelect={(id) => setSelectedId(id || null)}
          attack={flight}
          phase={flight ? "traveling" : "idle"}
          paused={scenario.phase === "paused"}
          marks={scenario.marks}
          frameKey={scenario.frameKey}
          frameIds={scenarioLive ? scenario.path : []}
        />
      ) : null}
      <div ref={dim} className="scene-dim" />
      <div ref={edge} className="edge-pulse">
        <span>Critical</span>
      </div>
    </div>
  );
}
