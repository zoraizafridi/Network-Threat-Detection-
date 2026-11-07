import { useEffect, useRef } from "react";
import { gsap } from "gsap";
import { capAlerts, groupAlerts, type FeedAlert } from "../alerts";
import { useReducedMotion } from "../useReducedMotion";

function tintFor(severity: string): string {
  if (severity === "CRITICAL") return "#A8321F";
  if (severity === "HIGH") return "#7A4F08";
  if (severity === "LOW") return "#3F6182";
  return "#2F6B45";
}

function AlertRow({ alert, count, fresh }: { alert: FeedAlert; count: number; fresh: boolean }) {
  const row = useRef<HTMLElement>(null);
  const wash = useRef<HTMLSpanElement>(null);
  const reduced = useReducedMotion();
  useEffect(() => {
    const line = row.current;
    const tint = wash.current;
    if (!line || !tint || !fresh) return;
    if (reduced) {
      gsap.set(line, { x: 0, autoAlpha: 1 });
      gsap.set(tint, { opacity: 0 });
      return;
    }
    const slide = gsap.fromTo(
      line,
      { x: -16, autoAlpha: 0 },
      { x: 0, autoAlpha: 1, duration: 0.3, ease: "power3.out" },
    );
    const fade = gsap.fromTo(tint, { opacity: 0.45 }, { opacity: 0, duration: 0.8, ease: "power3.out" });
    return () => {
      slide.kill();
      fade.kill();
    };
  }, [alert.id, fresh, reduced]);
  return (
    <article ref={row} className="feed-row" data-fresh={fresh && !reduced ? "yes" : "no"}>
      <span ref={wash} className="row-tint" style={{ background: tintFor(alert.severity) }} />
      <p className="mono">
        {alert.severity} {alert.attackType}
        {count > 1 ? ` x${count}` : ""}
      </p>
      <p className="small">
        {alert.sourceIp} to {alert.targetIp}
      </p>
      <p className="small muted">{alert.detectorName}</p>
    </article>
  );
}

export function AlertFeed({ alerts }: { alerts: FeedAlert[] }) {
  const groups = groupAlerts(capAlerts(alerts));
  return (
    <div className="feed" aria-live="polite">
      {groups.length === 0 ? <p className="muted">No alerts yet.</p> : null}
      {groups.map((group, index) => (
        <AlertRow
          key={`${group.key}-${group.latest.id}`}
          alert={group.latest}
          count={group.count}
          fresh={index === groups.length - 1}
        />
      ))}
    </div>
  );
}
