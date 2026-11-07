import { afterEach, describe, expect, test, vi } from "vitest";
import { request } from "../src/api";

function ok(body: unknown) {
  return { ok: true, status: 200, json: async () => body } as Response;
}

describe("csrf protected requests", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    document.cookie = "csrf=; Max-Age=0; path=/";
  });

  test("state changing requests carry the csrf token", async () => {
    document.cookie = "csrf=abc123";
    const fetchMock = vi.fn().mockResolvedValue(ok({}));
    vi.stubGlobal("fetch", fetchMock);
    await request("/api/sim/start", { method: "POST" });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect((init.headers as Headers).get("X-CSRF-Token")).toBe("abc123");
  });

  test("read requests stay token free", async () => {
    document.cookie = "csrf=abc123";
    const fetchMock = vi.fn().mockResolvedValue(ok([]));
    vi.stubGlobal("fetch", fetchMock);
    await request("/api/alerts");
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect((init.headers as Headers).has("X-CSRF-Token")).toBe(false);
  });
});
