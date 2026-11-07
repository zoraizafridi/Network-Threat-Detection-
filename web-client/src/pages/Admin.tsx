import { useEffect, useState } from "react";
import { EmptyState, Page, Panel } from "../components/ui";
import { readJson } from "../api";
import { accessDenied, canSeeAdmin } from "../permissions";
import { useApp } from "../store";

interface AdminConfig {
  thresholds: Record<string, string>;
  session: {
    timeoutSeconds: number;
    csrfEnabled: boolean;
    loginMaxAttempts: number;
    loginWindowSeconds: number;
  };
  accounts: { username: string; role: string }[];
}

export function AdminPage() {
  const role = useApp((state) => state.user?.role ?? "");
  const [config, setConfig] = useState<AdminConfig | null>(null);
  const [failed, setFailed] = useState(false);
  const allowed = canSeeAdmin(role);

  useEffect(() => {
    if (!allowed) return;
    readJson<AdminConfig>("/api/config")
      .then(setConfig)
      .catch(() => setFailed(true));
  }, [allowed]);

  if (!allowed) {
    return <p>{accessDenied(role)}</p>;
  }

  return (
    <Page title="Admin" description="Read only view of the detector thresholds, session policy, and configured accounts.">
      <Panel title="Detector thresholds">
        {failed ? <EmptyState>The configuration endpoint is unavailable.</EmptyState> : null}
        {!failed && !config ? <EmptyState>Loading configuration.</EmptyState> : null}
        {config ? (
          <table>
            <thead>
              <tr><th>Setting</th><th>Value</th></tr>
            </thead>
            <tbody>
              {Object.entries(config.thresholds).map(([key, value]) => (
                <tr key={key}><td>{key}</td><td>{value}</td></tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </Panel>
      <Panel title="Session policy">
        {config ? (
          <table>
            <thead>
              <tr><th>Setting</th><th>Value</th></tr>
            </thead>
            <tbody>
              <tr><td>Session timeout</td><td>{config.session.timeoutSeconds} seconds</td></tr>
              <tr><td>CSRF token required</td><td>{config.session.csrfEnabled ? "yes" : "no"}</td></tr>
              <tr><td>Login attempts before lockout</td><td>{config.session.loginMaxAttempts}</td></tr>
              <tr><td>Lockout window</td><td>{config.session.loginWindowSeconds} seconds</td></tr>
            </tbody>
          </table>
        ) : (
          <EmptyState>Loading session policy.</EmptyState>
        )}
      </Panel>
      <Panel title="Accounts" subtitle="Passwords are stored as PBKDF2 hashes and never returned by the API.">
        {config ? (
          <table>
            <thead>
              <tr><th>Username</th><th>Role</th></tr>
            </thead>
            <tbody>
              {config.accounts.map((account) => (
                <tr key={account.role}><td>{account.username}</td><td>{account.role}</td></tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState>Loading accounts.</EmptyState>
        )}
      </Panel>
    </Page>
  );
}
