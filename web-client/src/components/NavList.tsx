import { useLayoutEffect, useRef, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { navEntries, type NavEntry } from "../permissions";

const GROUPS: { title: string; labels: string[] }[] = [
  { title: "Monitoring", labels: ["Overview", "Alerts", "Flows", "Incidents", "Hosts"] },
  { title: "Operations", labels: ["Attack lab", "Planner", "Reports"] },
  { title: "System", labels: ["Control", "Admin"] },
];

const stroke = { fill: "none", stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };

function NavIcon({ name }: { name: string }) {
  return (
    <svg className="nav-ico" viewBox="0 0 24 24" aria-hidden="true">
      {name === "Overview" ? <path d="M4 10.5 12 4l8 6.5V20H4Z" {...stroke} /> : null}
      {name === "Alerts" ? <path d="M6 9a6 6 0 1 1 12 0c0 4 1.5 5.5 1.5 5.5H4.5S6 13 6 9ZM10 18a2 2 0 0 0 4 0" {...stroke} /> : null}
      {name === "Incidents" ? <path d="M12 4 3 19h18L12 4Zm0 6v4m0 2.5h.01" {...stroke} /> : null}
      {name === "Flows" ? <><circle cx="5" cy="7" r="1.8" {...stroke} /><circle cx="19" cy="17" r="1.8" {...stroke} /><path d="M6.6 8.1 17.4 15.9" {...stroke} /></> : null}
      {name === "Hosts" ? <><rect x="4" y="5" width="16" height="5" {...stroke} /><rect x="4" y="14" width="16" height="5" {...stroke} /></> : null}
      {name === "Attack lab" ? <><circle cx="12" cy="12" r="7" {...stroke} /><path d="M12 9v3l2 2" {...stroke} /></> : null}
      {name === "Planner" ? <path d="M8 6h11M8 12h11M8 18h11M5 6h.01M5 12h.01M5 18h.01" {...stroke} /> : null}
      {name === "Reports" ? <path d="M7 3h7l5 5v13H7V3Zm7 0v5h5" {...stroke} /> : null}
      {name === "Control" ? <path d="M4 8h16M4 16h16M8 8v.01M16 16v.01" {...stroke} /> : null}
      {name === "Admin" ? <path d="M12 3 5 6v6c0 4 3 6.5 7 8 4-1.5 7-4 7-8V6l-7-3Z" {...stroke} /> : null}
    </svg>
  );
}

export function NavList({
  role,
  alerts = 0,
  incidents = 0,
}: {
  role: string;
  alerts?: number;
  incidents?: number;
}) {
  const location = useLocation();
  const navRef = useRef<HTMLElement>(null);
  const [marker, setMarker] = useState({ top: 0, show: false });
  const entries = navEntries(role);
  const byLabel = new Map(entries.map((entry) => [entry.label, entry]));
  const groups = GROUPS.map((group) => ({
    title: group.title,
    entries: group.labels.map((label) => byLabel.get(label)).filter((entry): entry is NavEntry => Boolean(entry)),
  })).filter((group) => group.entries.length > 0);

  useLayoutEffect(() => {
    const nav = navRef.current;
    const active = nav?.querySelector<HTMLElement>("a[aria-current='page']");
    if (!nav || !active) {
      setMarker({ top: 0, show: false });
      return;
    }
    const navBox = nav.getBoundingClientRect();
    const box = active.getBoundingClientRect();
    setMarker({ top: box.top - navBox.top + nav.scrollTop, show: true });
  }, [location.pathname, role, alerts, incidents]);

  return (
    <nav ref={navRef} aria-label="Portal">
      <span className={marker.show ? "nav-marker" : "nav-marker is-off"} style={{ top: marker.top }} />
      {groups.map((group) => (
        <div key={group.title} className="nav-block">
          <p className="nav-group">{group.title}</p>
          <span className="nav-divider" />
          {group.entries.map((entry) => {
            const count = entry.label === "Alerts" ? alerts : entry.label === "Incidents" ? incidents : 0;
            return (
              <NavLink key={entry.to} to={entry.to} end={entry.to === "/portal"} data-label={entry.label}>
                <NavIcon name={entry.label} />
                <span className="nav-label">{entry.label}</span>
                {count > 0 ? <span className="nav-count">{count}</span> : null}
              </NavLink>
            );
          })}
        </div>
      ))}
    </nav>
  );
}
