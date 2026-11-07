import { describe, expect, test } from "vitest";
import { labelsOverlap, layoutNetwork } from "../src/layout";

const assets = [
  ["rt-core-1", "Core Router 1"],
  ["rt-core-2", "Core Router 2"],
  ["rt-dist-1", "Distribution Router 1"],
  ["srv-web-1", "Web Server 1"],
  ["srv-web-2", "Web Server 2"],
  ["srv-db-1", "Database Server 1"],
  ["srv-auth-1", "Auth Server 1"],
  ["ws-ops-1", "Ops Workstation 1"],
  ["ws-ops-2", "Ops Workstation 2"],
  ["ws-fin-1", "Finance Workstation 1"],
  ["ws-fin-2", "Finance Workstation 2"],
  ["ws-sec-1", "Security Workstation 1"],
  ["ws-dev-1", "Dev Workstation 1"],
  ["iot-cam-1", "Building Camera 1"],
  ["iot-cam-2", "Building Camera 2"],
  ["iot-sensor-1", "Temperature Sensor 1"],
  ["iot-sensor-2", "Humidity Sensor 1"],
  ["iot-badge-1", "Door Badge Reader 1"],
].map(([id, name]) => ({ id, name }));

const links = [
  ["link-r1-r2", "rt-core-1", "rt-core-2"],
  ["link-r2-r3", "rt-core-2", "rt-dist-1"],
  ["link-r3-r1", "rt-dist-1", "rt-core-1"],
  ["link-s1-r1", "srv-web-1", "rt-core-1"],
  ["link-w1-r3", "ws-ops-1", "rt-dist-1"],
  ["link-i1-r3", "iot-cam-1", "rt-dist-1"],
].map(([id, source, target]) => ({ id, source, target }));

describe("map layout", () => {
  test("is deterministic and keeps labels apart", () => {
    const first = layoutNetwork(assets, links);
    const second = layoutNetwork(assets.slice().reverse(), links.slice().reverse());
    expect(first.map((node) => [node.id, node.x, node.y, node.z, node.label])).toEqual(
      second.map((node) => [node.id, node.x, node.y, node.z, node.label]),
    );
    expect(labelsOverlap(first)).toBe(false);
    expect(first).toHaveLength(18);
  });
});
