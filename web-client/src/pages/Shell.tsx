import { useEffect, useRef, useState } from "react";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useReducedMotion } from "../useReducedMotion";
import { loadIncidents, loadState, request } from "../api";
import { NavList } from "../components/NavList";
import { usePortalData } from "../components/useStream";
import { canControlSimulation, navEntries } from "../permissions";
import { SimControls } from "./Control";
import { groupAlerts, type FeedAlert } from "../alerts";
import { attackLabel, relativeTime } from "../format";
import { StatusBadge } from "../components/ui";
import { useApp } from "../store";

export function Shell() {
  const navigate = useNavigate();
  const auth = useApp((state) => state.auth);
  const user = useApp((state) => state.user);
  const disconnected = useApp((state) => state.disconnected);
  const notice = useApp((state) => state.notice);
  const markSignedOut = useApp((state) => state.markSignedOut);

  useEffect(() => {
    loadState()
      .then(() => loadIncidents())
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (auth === "out") navigate("/login");
  }, [auth, navigate]);

  usePortalData(auth === "in");

  async function logout() {
    try {
      await request("/api/logout", { method: "POST" });
    } catch {
      /* session may already be gone */
    }
    markSignedOut();
    navigate("/login");
  }

  const assets = useApp((state) => state.assets);
  const alerts = useApp((state) => state.alerts);
  const role = user?.role ?? "";
  const roleLabel = role ? role.charAt(0).toUpperCase() + role.slice(1).toLowerCase() : "None";
  const location = useLocation();
  const reduced = useReducedMotion();
  const incidents = useApp((state) => state.incidents);
  const openIncidents = incidents.filter((row) => row.status === "OPEN").length;
  const [collapsed, setCollapsed] = useState(() => {
    try {
      const value = localStorage.getItem("fs-nav-collapsed");
      if (value === "1") return true;
      if (value !== null && value !== "0") localStorage.setItem("fs-nav-collapsed", "0");
      return false;
    } catch {
      return false;
    }
  });
  const [narrow, setNarrow] = useState(false);
  const [overlay, setOverlay] = useState(false);
  const [query, setQuery] = useState("");
  const [bellOpen, setBellOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const [readIds, setReadIds] = useState<string[]>([]);
  const [toasts, setToasts] = useState<FeedAlert[]>([]);
  const seenAlerts = useRef<Set<string> | null>(null);
  const setSelectedId = useApp((state) => state.setSelectedId);
  const unread = alerts.filter((alert) => !readIds.includes(alert.id));
  const bellGroups = groupAlerts([...alerts].reverse()).slice(0, 8);

  useEffect(() => {
    if (seenAlerts.current === null) {
      seenAlerts.current = new Set(alerts.map((alert) => alert.id));
      return;
    }
    const fresh = alerts.filter((alert) => !seenAlerts.current?.has(alert.id));
    fresh.forEach((alert) => seenAlerts.current?.add(alert.id));
    const critical = fresh.filter((alert) => alert.severity.toUpperCase().includes("CRIT") || alert.severity === "HIGH");
    if (critical.length === 0) return;
    setToasts((current) => [...critical, ...current].slice(0, 3));
  }, [alerts]);

  useEffect(() => {
    if (toasts.length === 0) return;
    const timer = window.setTimeout(() => setToasts((current) => current.slice(0, -1)), 6000);
    return () => window.clearTimeout(timer);
  }, [toasts]);

  function focusAlert(alert: FeedAlert) {
    const host = assets.find((asset) => asset.ip === alert.targetIp) ?? assets.find((asset) => asset.ip === alert.sourceIp);
    if (host) setSelectedId(host.id);
    setBellOpen(false);
    setToasts((current) => current.filter((row) => row.id !== alert.id));
    navigate("/portal");
  }
  const name = user?.username ?? "signed out";
  const needle = query.trim().toLowerCase();
  const hostHits = needle
    ? assets.filter((asset) => asset.name.toLowerCase().includes(needle) || asset.ip.includes(needle)).slice(0, 5)
    : [];
  const pageHits = needle
    ? navEntries(role).filter((entry) => entry.label.toLowerCase().includes(needle)).slice(0, 4)
    : [];

  useEffect(() => {
    const media = window.matchMedia("(max-width: 900px)");
    const apply = () => setNarrow(media.matches);
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, []);

  function toggleNav() {
    if (narrow) {
      setOverlay((open) => !open);
      return;
    }
    setCollapsed((value) => {
      const next = !value;
      try {
        localStorage.setItem("fs-nav-collapsed", next ? "1" : "0");
      } catch {
        /* storage unavailable */
      }
      return next;
    });
  }

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const typing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
      if (event.key === "Escape") {
        useApp.getState().setSelectedId(null);
        setOverlay(false);
        return;
      }
      if (typing || event.key !== "[") return;
      event.preventDefault();
      toggleNav();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [narrow]);

  const shellClass = [
    "shell",
    !narrow && collapsed ? "is-collapsed" : "",
    narrow ? "is-narrow" : "",
    overlay ? "nav-open" : "",
    reduced ? "reduced-motion" : "",
  ].filter(Boolean).join(" ");

  return (
    <div className={shellClass}>
      <aside className="sidebar">
        <p className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">Field Station</span>
        </p>
        <NavList role={role} alerts={alerts.length} incidents={openIncidents} />
        <div className="side-foot">
          <span className="side-version">1.0</span>
        </div>
      </aside>
      <div className="shell-main">
        <header className="topbar">
          <button type="button" className="nav-burger" onClick={toggleNav} aria-label={narrow ? (overlay ? "Close menu" : "Open menu") : (collapsed ? "Expand sidebar" : "Collapse sidebar")} aria-expanded={narrow ? overlay : !collapsed} aria-keyshortcuts="[">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg>
          </button>
          <form className="top-search" role="search" onSubmit={(event) => event.preventDefault()}>
            <input
              type="search"
              value={query}
              placeholder="Search hosts"
              aria-label="Search hosts"
              onChange={(event) => setQuery(event.target.value)}
            />
            {needle && (hostHits.length > 0 || pageHits.length > 0) ? (
              <div className="search-hits">
                {pageHits.map((entry) => (
                  <Link key={entry.to} to={entry.to} onClick={() => setQuery("")}>{entry.label}</Link>
                ))}
                {hostHits.map((asset) => (
                  <Link key={asset.id} to={`/portal/hosts/${asset.id}`} onClick={() => setQuery("")}>{asset.name}</Link>
                ))}
              </div>
            ) : null}
          </form>
          <div className="top-actions">
            <span className="top-status">
              <i className={disconnected ? "stream-dot is-down" : "stream-dot"} />
              {disconnected ? "Stream disconnected" : "Stream connected"}
            </span>
            {canControlSimulation(role) ? <SimControls /> : null}
            <div className="menu-anchor">
              <button type="button" className={unread.length > 0 ? "bell has-unread" : "bell"} aria-label="Alerts" aria-expanded={bellOpen} onClick={() => { setBellOpen((value) => !value); setUserOpen(false); }}>
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M6 9a6 6 0 1 1 12 0c0 4 1.5 5.5 1.5 5.5H4.5S6 13 6 9Z" />
                  <path d="M10 18a2 2 0 0 0 4 0" />
                </svg>
              </button>
              {bellOpen ? (
                <div className="menu-pop bell-pop" role="dialog" aria-label="Alerts">
                  <div className="row">
                    <strong>Alerts {unread.length > 0 ? `(${unread.length})` : ""}</strong>
                    <button type="button" onClick={() => setReadIds(alerts.map((alert) => alert.id))}>Mark all read</button>
                  </div>
                  {bellGroups.length === 0 ? <p>No alerts.</p> : bellGroups.map((group) => {
                    const alert = group.latest;
                    const source = assets.find((asset) => asset.ip === alert.sourceIp)?.name ?? alert.sourceIp;
                    const target = assets.find((asset) => asset.ip === alert.targetIp)?.name ?? alert.targetIp;
                    const stage = alert.description && !alert.description.includes("_") ? alert.description : "";
                    const simulation = alert.id.startsWith("sim-") || alert.detectorName === "Field station";
                    return (
                      <button key={alert.id} type="button" className="alert-pop-row" onClick={() => focusAlert(alert)}>
                        <span><StatusBadge status={alert.severity} /> {attackLabel(alert.attackType)}{group.count > 1 ? <i className="count-chip">x{group.count}</i> : null}</span>
                        <span>{source} → {target}{stage ? `, stage: ${stage}` : ""}</span>
                        <span className="mono" title={alert.timestamp}>{relativeTime(alert.timestamp)}{simulation ? " SIMULATION" : ""}</span>
                      </button>
                    );
                  })}
                  <Link to="/portal/alerts" onClick={() => setBellOpen(false)}>View all alerts</Link>
                </div>
              ) : null}
            </div>
            <div className="menu-anchor">
              <button type="button" className="user-menu" aria-expanded={userOpen} onClick={() => { setUserOpen((value) => !value); setBellOpen(false); }}>
                <span className="avatar">{name.slice(0, 1).toUpperCase()}</span>
                <span>{name}</span>
                <span className="role-chip">{roleLabel}</span>
              </button>
              {userOpen ? (
                <div className="menu-pop">
                  <button type="button" onClick={logout}>Log out</button>
                </div>
              ) : null}
            </div>
          </div>
        </header>
        <div className="toast-stack" aria-live="polite">
          {toasts.map((alert) => {
            const source = assets.find((asset) => asset.ip === alert.sourceIp)?.name ?? alert.sourceIp;
            const target = assets.find((asset) => asset.ip === alert.targetIp)?.name ?? alert.targetIp;
            return (
              <button key={alert.id} type="button" className="alert-pop-row" onClick={() => focusAlert(alert)}>
                <span><StatusBadge status={alert.severity} /> {attackLabel(alert.attackType)}</span>
                <span>{source} → {target}</span>
                <span className="mono" title={alert.timestamp}>{relativeTime(alert.timestamp)}</span>
              </button>
            );
          })}
        </div>
        <div className="content">
          {disconnected ? <p className="stream-down">Stream disconnected. Live data is stale and the client is retrying.</p> : null}
          {notice ? <p className="notice">{notice}</p> : null}
          {auth === "unknown" ? <p>Checking session.</p> : (
            <div key={location.pathname} className="page-fade">
              <Outlet />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
