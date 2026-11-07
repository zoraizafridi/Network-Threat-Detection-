import { useState } from "react";
import { resetAttackState } from "../attackPhase";
import { HttpStatusError, loadState, request } from "../api";
import { scenarioHalt, scenarioReset, scenarioSetLoop, scenarioStart } from "../scenario";
import { Page } from "../components/ui";
import { accessDenied, canControlSimulation } from "../permissions";
import { useApp } from "../store";

export function SimControls() {
  const role = useApp((state) => state.user?.role ?? "");
  const autoMode = useApp((state) => state.autoMode);
  const setNotice = useApp((state) => state.setNotice);

  async function post(path: string, body?: string) {
    setNotice("");
    try {
      await request(path, { method: "POST", body });
      await loadState();
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 403) setNotice(accessDenied(role));
    }
  }

  const running = useApp((state) => state.running);
  const [open, setOpen] = useState(false);
  const stateLabel = autoMode ? "auto" : running ? "running" : "stopped";

  return (
    <div className="sim-control" aria-label="Simulation">
      <i className={running ? "stream-dot" : "stream-dot is-idle"} />
      <span>Simulation: {stateLabel}</span>
      {autoMode ? <em className="auto-chip">Auto</em> : null}
      <button
        type="button"
        className="primary"
        onClick={() => {
          if (running) {
            scenarioHalt();
            void post("/api/sim/stop");
          } else {
            scenarioStart(false);
            void post("/api/sim/start");
          }
        }}
      >
        {running ? "Stop" : "Start"}
      </button>
      <button type="button" className="chevron" aria-label="Simulation menu" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg>
      </button>
      {open ? (
        <div className="menu-pop" role="menu">
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              const next = !autoMode;
              if (next) {
                scenarioSetLoop(true);
                void post("/api/sim/start");
              } else {
                scenarioSetLoop(false);
              }
              void post("/api/sim/auto", JSON.stringify({ on: next }));
              setOpen(false);
            }}
          >
            {autoMode ? "✓ " : ""}Auto mode
          </button>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              scenarioReset();
              resetAttackState();
              void post("/api/sim/reset");
              setOpen(false);
            }}
          >
            Reset simulation
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function ControlPage() {
  const role = useApp((state) => state.user?.role ?? "");
  const running = useApp((state) => state.running);
  const autoMode = useApp((state) => state.autoMode);

  if (!canControlSimulation(role)) {
    return <p>{accessDenied(role)}</p>;
  }

  return (
    <Page title="Control" description="Simulation state is changed from the top bar. This page only explains the current mode.">
      <p>{running ? "The simulation is running." : "The simulation is stopped."}</p>
      <p>{autoMode ? "Auto mode is on. The server chooses when to emit events." : "Auto mode is off. Events run only when you start the simulation or launch an attack."}</p>
    </Page>
  );
}
