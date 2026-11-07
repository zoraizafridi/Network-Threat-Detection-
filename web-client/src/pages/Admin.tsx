import { EmptyState, Page, Panel } from "../components/ui";
import { accessDenied, canSeeAdmin } from "../permissions";
import { useApp } from "../store";

export function AdminPage() {
  const role = useApp((state) => state.user?.role ?? "");
  if (!canSeeAdmin(role)) {
    return <p>{accessDenied(role)}</p>;
  }
  return (
    <Page title="Admin" description="Settings the API does not expose stay empty rather than showing placeholders.">
      <Panel title="Detector thresholds"><EmptyState>The API does not expose configuration.</EmptyState></Panel>
      <Panel title="Users"><EmptyState>User administration is not available from the API.</EmptyState></Panel>
      <Panel title="Event log"><EmptyState>The API does not expose the event log.</EmptyState></Panel>
    </Page>
  );
}
