import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { sessionAfterStatus } from "../src/session";

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return files(path);
    return path.endsWith(".ts") || path.endsWith(".tsx") || path.endsWith(".css") ? [path] : [];
  });
}

describe("session", () => {
  test("a 401 clears the session", () => {
    expect(sessionAfterStatus({ username: "admin", role: "Admin" }, 401)).toBeNull();
    expect(sessionAfterStatus({ username: "admin", role: "Admin" }, 200)).toEqual({
      username: "admin",
      role: "Admin",
    });
  });

  test("the client keeps the session in memory and does not use browser storage", () => {
    const stored = files(join(process.cwd(), "src")).filter((path) => {
      const text = readFileSync(path, "utf8");
      return text.includes("localStorage") || text.includes("sessionStorage");
    });
    expect(stored.every((path) => path.endsWith("Shell.tsx"))).toBe(true);
    const shell = stored.length ? readFileSync(stored[0], "utf8") : "";
    expect(shell.includes("fs-nav-collapsed")).toBe(true);
    expect(shell.includes("sessionStorage")).toBe(false);
  });
});
