import { useEffect, useRef, useState } from "react";
import { BrowserRouter, Route, Routes, useLocation, type Location } from "react-router-dom";
import { gsap } from "gsap";
import { ENTER_MS, LEAVE_MS, STAGGER_S } from "./scene";
import { AdminPage } from "./pages/Admin";
import { AlertsPage } from "./pages/Alerts";
import { AttackLab } from "./pages/AttackLab";
import { ControlPage } from "./pages/Control";
import { HostDetail, HostsPage } from "./pages/Hosts";
import { IncidentsPage } from "./pages/Incidents";
import { SceneHost } from "./components/SceneHost";
import { Landing } from "./pages/Landing";
import { Login } from "./pages/Login";
import { Roles } from "./pages/Roles";
import { Overview } from "./pages/Overview";
import { PlannerPage } from "./pages/Planner";
import { ReportsPage } from "./pages/Reports";
import { Shell } from "./pages/Shell";
import { useReducedMotion } from "./useReducedMotion";

function RouteStage() {
  const location = useLocation();
  const reduced = useReducedMotion();
  const panel = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState<Location>(location);
  const first = useRef(true);

  useEffect(() => {
    if (shown.pathname === location.pathname && shown.key === location.key) return;
    const insidePortal = shown.pathname.startsWith("/portal") && location.pathname.startsWith("/portal");
    if (insidePortal) {
      setShown(location);
      return;
    }
    const el = panel.current;
    if (!el || reduced || first.current) {
      first.current = false;
      gsap.set(el, { y: 0, autoAlpha: 1 });
      setShown(location);
      return;
    }
    const tween = gsap.to(el, {
      y: -8,
      autoAlpha: 0,
      duration: LEAVE_MS / 1000,
      ease: "power3.out",
      onComplete: () => setShown(location),
    });
    return () => tween.kill();
  }, [location, reduced, shown.key, shown.pathname]);

  useEffect(() => {
    const el = panel.current;
    if (!el || first.current) return;
    if (reduced) {
      gsap.set(el, { y: 0, autoAlpha: 1 });
      return;
    }
    const bits = el.querySelectorAll("[data-stagger]");
    const enter = gsap.fromTo(
      el,
      { y: 8, autoAlpha: 0 },
      { y: 0, autoAlpha: 1, duration: ENTER_MS / 1000, ease: "power3.out" },
    );
    const stagger = bits.length
      ? gsap.fromTo(
          bits,
          { y: 8, autoAlpha: 0 },
          { y: 0, autoAlpha: 1, duration: ENTER_MS / 1000, stagger: STAGGER_S, ease: "power3.out" },
        )
      : null;
    return () => {
      enter.kill();
      stagger?.kill();
    };
  }, [shown.key, reduced]);

  return (
    <div className="app-stage">
      <div ref={panel} className="route-stage">
        <AppRoutes location={shown} />
      </div>
    </div>
  );
}

export function AppRoutes({ location }: { location?: Location }) {
  return (
    <Routes location={location}>
      <Route path="/" element={<Landing />} />
      <Route path="/roles" element={<Roles />} />
      <Route path="/login" element={<Login />} />
      <Route path="/portal" element={<Shell />}>
        <Route index element={<Overview />} />
        <Route path="attack" element={<AttackLab />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="hosts" element={<HostsPage />} />
        <Route path="hosts/:id" element={<HostDetail />} />
        <Route path="planner" element={<PlannerPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="control" element={<ControlPage />} />
        <Route path="admin" element={<AdminPage />} />
      </Route>
    </Routes>
  );
}

export function AppTree() {
  return (
    <>
      <SceneHost />
      <RouteStage />
    </>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AppTree />
    </BrowserRouter>
  );
}
