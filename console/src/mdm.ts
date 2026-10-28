// What Intune says about the Macs, for the views that set it beside what Altiward knows.
// Viewers see this too: each Mac's serial, name, primary user and last check-in, never the IDs
// that identify it to Intune (the API doesn't send them).

import { useMemo } from "react";
import type { MDMDevice, MDMStatus } from "./api";
import { useApi } from "./context";
import { useLoad } from "./useLoad";

/** A serial as the server matches it: without surrounding spaces, upper-cased. */
export const normaliseSerial = (s: string): string => s.trim().toUpperCase();

/** The copy by serial. Intune can list a serial twice, so each keeps the record with the newest
 *  check-in; one that never checked in is the oldest. */
export function bySerial(devices: MDMDevice[]): Map<string, MDMDevice> {
  const at = (d: MDMDevice) => (d.last_check_in ? new Date(d.last_check_in).getTime() : -Infinity);
  const out = new Map<string, MDMDevice>();
  for (const d of devices) {
    const key = normaliseSerial(d.serial);
    const kept = out.get(key);
    if (!kept || at(d) > at(kept)) out.set(key, d);
  }
  return out;
}

/** Whether the copy can say a Mac is missing: Intune is connected and has synced at least once. */
export const hasSynced = (status: MDMStatus | undefined): boolean => !!status?.configured && !!status.last_success_at;

/** The Intune connection, and its Macs by serial. Without a connection, `bySerial` is empty
 *  whatever the server holds, and so while loading, or if the server can't say. */
export function useMDM(): { status: MDMStatus | undefined; bySerial: Map<string, MDMDevice> } {
  const api = useApi();
  const { data } = useLoad(async () => {
    const status = await api.mdmStatus();
    return { status, devices: status.configured ? await api.mdmDevices() : [] };
  }, [], 60_000);
  const devices = data?.devices;
  const map = useMemo(() => bySerial(devices ?? []), [devices]);
  return { status: data?.status, bySerial: map };
}
