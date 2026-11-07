export function attackLabel(type: string): string {
  const key = type.toUpperCase();
  if (key.includes("DOS")) return "DoS flood";
  if (key.includes("BRUTE")) return "Brute force";
  if (key.includes("PORT")) return "Port scan";
  if (key.includes("DATA")) return "Data transfer";
  if (key.includes("INTRUSION") || key.includes("CRITICAL_INTRUSION")) return "Critical intrusion";
  return type
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function statusLabel(status: string): string {
  const key = status.toUpperCase();
  if (key === "NORMAL" || key === "HEALTHY") return "Healthy";
  if (key === "SUSPICIOUS") return "Probed";
  if (key === "COMPROMISED") return "Compromised";
  if (key === "OPEN") return "Open";
  if (key === "CLOSED") return "Closed";
  if (key === "MITIGATED") return "Mitigated";
  if (key === "HIGH") return "High";
  if (key === "LOW") return "Low";
  if (key === "CRITICAL") return "Critical";
  if (key === "MEDIUM" || key === "WARN" || key === "DEGRADED") return key === "DEGRADED" ? "Degraded" : key === "WARN" ? "Warning" : "Medium";
  return attackLabel(status);
}

export function clockTime(iso: string): string {
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  return when.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function relativeTime(iso: string): string {
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return "Unknown";
  const seconds = Math.max(0, Math.round((Date.now() - time) / 1000));
  if (seconds < 5) return "Just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return "Earlier";
}
