import type { ReactNode } from "react";
import { statusLabel } from "../format";

export function Page({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <section className="page">
      <header className="page-head">
        <h1>{title}</h1>
        {description ? <p>{description}</p> : null}
      </header>
      {children}
    </section>
  );
}

export function Panel({
  title,
  subtitle,
  action,
  children,
  className,
}: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={className ? `panel ${className}` : "panel"}>
      {title ? (
        <header className="card-head">
          <span className="card-ico" aria-hidden="true">
            <svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg>
          </span>
          <span className="card-titles">
            <h2>{title}</h2>
            {subtitle ? <p>{subtitle}</p> : null}
          </span>
          {action}
        </header>
      ) : null}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const key = status.toUpperCase();
  const tone =
    key.includes("CRIT") || key === "COMPROMISED" || key === "HIGH"
      ? "critical"
      : key.includes("SUSPIC") || key === "WARN" || key === "DEGRADED" || key === "OPEN"
        ? "warn"
        : key === "NORMAL" || key === "LOW" || key === "HEALTHY" || key === "CLOSED" || key === "MITIGATED"
          ? "ok"
          : "isolated";
  const label = statusLabel(status);
  const quiet = key === "NORMAL" || key === "HEALTHY";
  return (
    <span className={`badge ${tone}${quiet ? " is-quiet" : ""}`} title={label}>
      <i />
      {quiet ? null : label}
    </span>
  );
}

export function MapPanel({
  title,
  subtitle,
  children,
  className,
}: {
  title: string;
  subtitle?: string;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <Panel title={title} subtitle={subtitle} className={className ? `map-panel ${className}` : "map-panel"}>
      <div className="map-canvas">{children}</div>
    </Panel>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="empty-state">{children}</p>;
}

export function sentence(value: string): string {
  return value
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
