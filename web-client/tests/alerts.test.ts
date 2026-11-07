import { describe, expect, test } from "vitest";
import { capAlerts, groupAlerts, type FeedAlert } from "../src/alerts";

function alert(id: string, source = "10.0.0.1", target = "10.0.0.2", attackType = "DOS_FLOOD"): FeedAlert {
  return {
    id,
    timestamp: "2026-01-01T00:00:00Z",
    severity: "HIGH",
    attackType,
    sourceIp: source,
    targetIp: target,
    detectorName: "SignatureDetector",
    description: id,
  };
}

describe("alert feed", () => {
  test("caps the feed at 500 and keeps the newest", () => {
    const alerts = Array.from({ length: 520 }, (_, index) => alert(String(index)));
    const capped = capAlerts(alerts);
    expect(capped).toHaveLength(500);
    expect(capped[0].id).toBe("20");
    expect(capped[499].id).toBe("519");
  });

  test("groups consecutive alerts with the same source, target and type", () => {
    const groups = groupAlerts([
      alert("a"),
      alert("b"),
      alert("c", "10.0.0.1", "10.0.0.2", "PORT_SCAN"),
      alert("d", "10.0.2.1", "10.0.1.10", "PORT_SCAN"),
    ]);
    expect(groups.map((group) => group.count)).toEqual([2, 1, 1]);
    expect(groups[0].latest.id).toBe("b");
    expect(groups[0].alerts.map((item) => item.id)).toEqual(["a", "b"]);
  });
});
