import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, test } from "vitest";
import { AttackLab } from "../src/pages/AttackLab";
import { useApp } from "../src/store";

const hosts = [
  { id: "a", name: "Host A", ip: "10.0.0.1", type: "SERVER", criticality: 1, riskScore: 0, status: "NORMAL" },
  { id: "b", name: "Host B", ip: "10.0.0.2", type: "ROUTER", criticality: 1, riskScore: 0, status: "NORMAL" },
];

describe("attack launch", () => {
  test("Launch is disabled with an invalid selection", () => {
    useApp.setState({
      auth: "in",
      user: { username: "admin", role: "Admin" },
      assets: hosts,
      alerts: [],
      notice: "",
    });
    render(<AttackLab />);
    const launch = screen.getByRole("button", { name: "Launch" });
    expect(launch).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Source/), { target: { value: "a" } });
    fireEvent.change(screen.getByLabelText(/Target/), { target: { value: "a" } });
    expect(launch).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Target/), { target: { value: "b" } });
    expect(launch).not.toBeDisabled();
  });
});
