import { useEffect } from "react";
import type { FeedAlert } from "../alerts";
import { applyState, loadAlerts, loadIncidents, loadNetwork, type StateBody } from "../api";
import { useApp } from "../store";
import type { Asset, ContainedAddress, IncidentRow, NetLink } from "../types";

export function usePortalData(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    let source: EventSource | null = null;
    let timer = 0;
    let stopped = false;

    const connect = () => {
      source = new EventSource("/api/stream");
      source.addEventListener("open", () => useApp.getState().setDisconnected(false));
      source.addEventListener("alert", (event) => {
        const payload = parse<FeedAlert>((event as MessageEvent).data);
        if (payload) useApp.getState().pushAlert(payload);
      });
      source.addEventListener("network", (event) => {
        const payload = parse<{ assets: Asset[]; links: NetLink[]; contained?: ContainedAddress[] }>(
          (event as MessageEvent).data,
        );
        if (payload?.assets && payload.links) {
          useApp
            .getState()
            .setNetwork(payload.assets, payload.links, undefined, (payload.contained ?? []).map((entry) => entry.ip));
        }
      });
      source.addEventListener("state", (event) => {
        const payload = parse<StateBody>((event as MessageEvent).data);
        if (payload) applyState(payload);
      });
      source.addEventListener("incidents", (event) => {
        const payload = parse<IncidentRow[]>((event as MessageEvent).data);
        if (payload) useApp.getState().setIncidents(payload);
      });
      source.onerror = () => {
        useApp.getState().setDisconnected(true);
        source?.close();
        if (!stopped) timer = window.setTimeout(connect, 1000);
      };
    };

    connect();
    loadNetwork().catch(() => undefined);
    loadAlerts().catch(() => undefined);
    loadIncidents().catch(() => undefined);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      source?.close();
    };
  }, [active]);
}

function parse<T>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}
