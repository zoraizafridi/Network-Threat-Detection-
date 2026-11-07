/** Reads a colour token from the single token block in styles.css. */
export function cssToken(name: string, fallback: string): string {
  if (typeof window === "undefined" || typeof window.getComputedStyle !== "function") return fallback;
  const value = window.getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}
