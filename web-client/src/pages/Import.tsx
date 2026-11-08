import { useCallback, useEffect, useRef, useState } from "react";
import {
  HttpStatusError,
  loadAlerts,
  loadImportSample,
  loadImportStatus,
  loadNetwork,
  startImport,
  type ImportReport,
  type ImportStatus,
} from "../api";
import { EmptyState, Page, Panel } from "../components/ui";
import { accessDenied, canControlSimulation } from "../permissions";
import { useApp } from "../store";

const POLL_MS = 1500;

interface Picked {
  name: string;
  text: string;
}

function reportKey(report: ImportReport): string {
  return `${report.source}|${report.events}|${report.alerts}|${report.elapsedMillis}|${report.completed}`;
}

function sizeLabel(text: string): string {
  const bytes = new Blob([text]).size;
  return bytes < 1024 ? `${bytes} bytes` : `${Math.round(bytes / 1024)} KB`;
}

function DropZone({
  title,
  hint,
  accept,
  picked,
  onPick,
  disabled,
}: {
  title: string;
  hint: string;
  accept: string;
  picked: Picked | null;
  onPick: (picked: Picked | null) => void;
  disabled?: boolean;
}) {
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const read = useCallback(
    async (file: File | undefined) => {
      if (!file) return;
      onPick({ name: file.name, text: await file.text() });
    },
    [onPick],
  );

  return (
    <div
      className={over ? "import-drop is-over" : "import-drop"}
      aria-disabled={disabled}
      onDragOver={(event) => {
        event.preventDefault();
        if (!disabled) setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(event) => {
        event.preventDefault();
        setOver(false);
        if (!disabled) void read(event.dataTransfer.files[0]);
      }}
    >
      <strong>{title}</strong>
      <p className="muted">
        {picked ? `${picked.name}, ${sizeLabel(picked.text)}` : hint}
      </p>
      <div className="row">
        <button type="button" className="secondary" disabled={disabled} onClick={() => input.current?.click()}>
          {picked ? "Replace file" : "Choose file"}
        </button>
        {picked ? (
          <button type="button" className="secondary" disabled={disabled} onClick={() => onPick(null)}>
            Clear
          </button>
        ) : null}
      </div>
      <input
        ref={input}
        type="file"
        accept={accept}
        hidden
        onChange={(event) => {
          void read(event.target.files?.[0]);
          event.target.value = "";
        }}
      />
    </div>
  );
}

function stateSentence(status: ImportStatus | null): string {
  if (!status) return "Reading the importer state.";
  switch (status.state) {
    case "RUNNING":
      return `Replaying ${status.replayed} of ${status.flows} connections.`;
    case "DONE":
      return "The last replay finished.";
    case "CANCELLED":
      return "The last replay was stopped before it finished.";
    case "FAILED":
      return status.error ?? "The last replay failed.";
    default:
      return "No replay has run in this session.";
  }
}

export function ImportPage() {
  const role = useApp((state) => state.user?.role ?? "");
  const setNotice = useApp((state) => state.setNotice);
  const [connLog, setConnLog] = useState<Picked | null>(null);
  const [labels, setLabels] = useState<Picked | null>(null);
  const [speed, setSpeed] = useState("0");
  const [status, setStatus] = useState<ImportStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const seen = useRef<string | null>(null);

  useEffect(() => {
    let stop = false;
    async function tick() {
      try {
        const body = await loadImportStatus();
        if (stop) return;
        setStatus(body);
        const report = body.lastReport;
        if (report && seen.current !== reportKey(report)) {
          seen.current = reportKey(report);
          void loadNetwork().catch(() => undefined);
          void loadAlerts().catch(() => undefined);
        }
      } catch {
      }
    }
    void tick();
    const timer = window.setInterval(() => void tick(), POLL_MS);
    return () => {
      stop = true;
      window.clearInterval(timer);
    };
  }, []);

  const running = status?.state === "RUNNING";
  const report = status?.lastReport ?? null;
  const started = status !== null && status.state !== "IDLE";

  async function start() {
    if (!connLog) {
      setNotice("Choose a connection log first.");
      return;
    }
    setNotice("");
    setBusy(true);
    try {
      const multiplier = Number.parseFloat(speed);
      const body = await startImport({
        connLog: connLog.text,
        labels: labels?.text,
        source: connLog.name,
        labelsName: labels?.name,
        speed: Number.isFinite(multiplier) ? multiplier : 0,
      });
      setStatus({ ...body, lastReport: report });
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 403) setNotice(accessDenied(role));
      else if (error instanceof HttpStatusError && error.status === 409) setNotice("A replay is already running.");
      else if (error instanceof HttpStatusError && error.status === 413) setNotice("That log is larger than the server accepts.");
      else setNotice("The replay could not be started.");
    } finally {
      setBusy(false);
    }
  }

  async function useSample() {
    setNotice("");
    setBusy(true);
    try {
      const sample = await loadImportSample();
      setConnLog({ name: sample.source, text: sample.connLog });
      setLabels(sample.labels ? { name: sample.labelsName, text: sample.labels } : null);
    } catch {
      setNotice("The bundled sample could not be loaded.");
    } finally {
      setBusy(false);
    }
  }

  if (!canControlSimulation(role)) {
    return (
      <Page title="Import">
        <p>{accessDenied(role)}</p>
      </Page>
    );
  }

  return (
    <Page
      title="Import"
      description="Replay an exported Zeek conn log through the live pipeline. Labels are joined after the run and never reach a detector."
    >
      <div className="board-12">
        <Panel className="span-6" title="Connection log" subtitle="Zeek conn.log, tab separated">
          <DropZone
            title="Drop a conn.log"
            hint="The file stays in the browser until you start the replay."
            accept=".log,.txt,text/plain"
            picked={connLog}
            onPick={setConnLog}
            disabled={running}
          />
        </Panel>
        <Panel className="span-6" title="Ground-truth labels" subtitle="Optional uid,label pairs">
          <DropZone
            title="Drop a labels file"
            hint="Without it every flow is counted as UNLABELLED."
            accept=".csv,.txt,text/csv,text/plain"
            picked={labels}
            onPick={setLabels}
            disabled={running}
          />
        </Panel>
      </div>

      <div className="row no-print">
        <label className="row" htmlFor="import-speed">
          <span className="muted">Pace</span>
          <select id="import-speed" value={speed} disabled={running} onChange={(event) => setSpeed(event.target.value)}>
            <option value="0">As fast as possible</option>
            <option value="1">Recorded pace</option>
            <option value="10">10 times</option>
            <option value="60">60 times</option>
            <option value="600">600 times</option>
          </select>
        </label>
        <button type="button" className="primary" disabled={busy || running || !connLog} onClick={() => void start()}>
          {running ? "Replaying" : "Start replay"}
        </button>
        <button type="button" className="secondary" disabled={busy || running} onClick={() => void useSample()}>
          Use the bundled sample
        </button>
      </div>

      <Panel
        title="Progress"
        subtitle={stateSentence(status)}
        action={running ? <span className="badge warn"><i />Running</span> : null}
      >
        {started ? (
          <>
            <div
              className="import-progress"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round((status?.progress ?? 0) * 100)}
            >
              <i style={{ width: `${Math.round((status?.progress ?? 0) * 100)}%` }} />
            </div>
            <p className="muted">
              {running
                ? `${status?.replayed ?? 0} connections, ${status?.alerts ?? 0} alerts so far. Resetting the simulation stops a replay.`
                : "A replay runs on the server. The topology and the alert feed refresh when it finishes."}
            </p>
          </>
        ) : (
          <p className="muted">
            Choose a connection log, then start the replay. The bar tracks the file while the server works through it.
          </p>
        )}
      </Panel>

      {report ? (
        <>
          <div className="stat-row">
            <article className="stat-tile"><strong className="stat-value">{report.flows}</strong><span>Flows parsed</span></article>
            <article className="stat-tile"><strong className="stat-value">{report.events}</strong><span>Events replayed</span></article>
            <article className="stat-tile"><strong className="stat-value">{report.alerts}</strong><span>Alerts delivered</span></article>
            <article className="stat-tile"><strong className="stat-value">{report.unknownHosts}</strong><span>New hosts</span></article>
          </div>

          <Panel
            title="Per-label result"
            subtitle={
              `${report.source}${report.labelsSource ? ` with ${report.labelsSource}` : " without labels"}, `
              + `${report.elapsedMillis} ms, ${report.detected} detected, ${report.folded} folded, `
              + `${report.stored} rows stored`
            }
          >
            {report.labels.length === 0 ? (
              <EmptyState>No labelled connections in that file.</EmptyState>
            ) : (
              <table className="flow-table import-labels">
                <thead>
                  <tr>
                    <th>Label</th>
                    <th>Flows</th>
                    <th>Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {report.labels.map((row) => (
                    <tr key={row.label}>
                      <td className="mono">{row.label}</td>
                      <td className="mono">{row.flows}</td>
                      <td className="mono">{row.alerts}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {report.unknownHostIps.length > 0 ? (
              <p className="muted">
                Added to the topology: {report.unknownHostIps.slice(0, 8).join(", ")}
                {report.unknownHostIps.length > 8 ? ` and ${report.unknownHostIps.length - 8} more` : ""}.
                A simulation reset removes them again.
              </p>
            ) : null}
            {report.problems.length > 0 ? (
              <ul className="import-problems">
                {report.problems.map((problem) => <li key={problem}>{problem}</li>)}
              </ul>
            ) : null}
          </Panel>
        </>
      ) : null}
    </Page>
  );
}
