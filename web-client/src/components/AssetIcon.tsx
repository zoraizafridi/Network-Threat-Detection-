import type { ReactNode } from "react";

function Svg({ label, children }: { label: string; children: ReactNode }) {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden={label ? undefined : true} role="img">
      <title>{label}</title>
      {children}
    </svg>
  );
}

const stroke = { fill: "none", stroke: "currentColor", strokeWidth: 1.5 };

export function AssetIcon({ type, label }: { type: string; label: string }) {
  if (type === "SERVER") {
    return (
      <Svg label={label}>
        <rect x="2" y="2" width="12" height="4" {...stroke} />
        <rect x="2" y="8" width="12" height="4" {...stroke} />
      </Svg>
    );
  }
  if (type === "WORKSTATION") {
    return (
      <Svg label={label}>
        <rect x="2" y="3" width="12" height="7" {...stroke} />
        <path d="M5 13h6" {...stroke} />
      </Svg>
    );
  }
  if (type === "ROUTER") {
    return (
      <Svg label={label}>
        <ellipse cx="8" cy="8" rx="5" ry="3" {...stroke} />
        <path d="M8 5v6" {...stroke} />
      </Svg>
    );
  }
  return (
    <Svg label={label}>
      <path d="M8 2 L14 8 L8 14 L2 8 Z" {...stroke} />
    </Svg>
  );
}

export function statusClass(status: string): string {
  if (status === "SUSPICIOUS") return "status-suspicious";
  if (status === "COMPROMISED") return "status-compromised";
  if (status === "LOW") return "status-low";
  return "status-normal";
}
