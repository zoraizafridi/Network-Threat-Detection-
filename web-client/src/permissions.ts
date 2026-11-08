export function canLaunchAttack(role: string): boolean {
  return role === "Admin" || role === "Analyst";
}

export function canRunPlanner(role: string): boolean {
  return role === "Admin" || role === "Analyst";
}

export function canControlSimulation(role: string): boolean {
  return canLaunchAttack(role) || canRunPlanner(role);
}

export function canSeeAdmin(role: string): boolean {
  return role === "Admin";
}

export interface NavEntry {
  label: string;
  to: string;
}

const ENTRIES: { label: string; to: string; allow: (role: string) => boolean }[] = [
  { label: "Overview", to: "/portal", allow: () => true },
  { label: "Attack lab", to: "/portal/attack", allow: canLaunchAttack },
  { label: "Alerts", to: "/portal/alerts", allow: () => true },
  { label: "Flows", to: "/portal/flows", allow: () => true },
  { label: "Incidents", to: "/portal/incidents", allow: () => true },
  { label: "Hosts", to: "/portal/hosts", allow: () => true },
  { label: "Planner", to: "/portal/planner", allow: canRunPlanner },
  { label: "Reports", to: "/portal/reports", allow: () => true },
  { label: "Control", to: "/portal/control", allow: canControlSimulation },
  { label: "Admin", to: "/portal/admin", allow: canSeeAdmin },
];

export function navEntries(role: string): NavEntry[] {
  return ENTRIES.filter((entry) => entry.allow(role)).map((entry) => ({
    label: entry.label,
    to: entry.to,
  }));
}

export function accessDenied(role: string): string {
  return `Access denied for role ${role}`;
}
