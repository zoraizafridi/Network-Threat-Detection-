import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, type Location } from "react-router-dom";
import { gsap } from "gsap";
import { ENTER_MS, LEAVE_MS, STAGGER_S } from "./scene";
import { Landing } from "./pages/Landing";
import { Login } from "./pages/Login";
import { Roles } from "./pages/Roles";
import { useReducedMotion } from "./useReducedMotion";

const Shell = lazy(() => import("./pages/Shell").then((module) => ({ default: module.Shell })));
const Overview = lazy(() => import("./pages/Overview").then((module) => ({ default: module.Overview })));
const AttackLab = lazy(() => import("./pages/AttackLab").then((module) => ({ default: module.AttackLab })));
const AlertsPage = lazy(() => import("./pages/Alerts").then((module) => ({ default: module.AlertsPage })));
const FlowsPage = lazy(() => import("./pages/Flows").then((module) => ({ default: module.FlowsPage })));
const IncidentsPage = lazy(() => import("./pages/Incidents").then((module) => ({ default: module.IncidentsPage })));
const HostsPage = lazy(() => import("./pages/Hosts").then((module) => ({ default: module.HostsPage })));
const HostDetail = lazy(() => import("./pages/Hosts").then((module) => ({ default: module.HostDetail })));
const PlannerPage = lazy(() => import("./pages/Planner").then((module) => ({ default: module.PlannerPage })));
const ReportsPage = lazy(() => import("./pages/Reports").then((module) => ({ default: module.ReportsPage })));
const ControlPage = lazy(() => import("./pages/Control").then((module) => ({ default: module.ControlPage })));
const AdminPage = lazy(() => import("./pages/Admin").then((module) => ({ default: module.AdminPage })));

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
    return () => { tween.kill(); };
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
        <Suspense fallback={<p className="route-loading">Loading</p>}>
          <AppRoutes location={shown} />
        </Suspense>
      </div>
    </div>
  );
}

function PortalNotFound() {
  return (
    <section className="page">
      <header className="page-head">
        <h1>Not found</h1>
        <p>That portal route does not exist.</p>
      </header>
      <p><Link to="/portal">Back to overview</Link></p>
    </section>
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
        <Route path="flows" element={<FlowsPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="hosts" element={<HostsPage />} />
        <Route path="hosts/:id" element={<HostDetail />} />
        <Route path="planner" element={<PlannerPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="control" element={<ControlPage />} />
        <Route path="admin" element={<AdminPage />} />
        <Route path="*" element={<PortalNotFound />} />
      </Route>
      {/* Legacy address. Kept outside the portal subtree so the redirect does not
          run inside the lazily loaded Shell, where the Suspense retry would
          swallow the Navigate effect and leave the old URL in place. */}
      <Route path="/portal/overview" element={<Navigate to="/portal" replace />} />
    </Routes>
  );
}

export function AppTree() {
  return <RouteStage />;
}

export function App() {
  return (
    <BrowserRouter>
      <AppTree />
    </BrowserRouter>
  );
}
