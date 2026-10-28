import type { AuditEntry } from "../api";
import { Banner, Empty, Toolbar } from "../components/Chrome";
import { Table } from "../components/Table";
import { useApi } from "../context";
import { dateTime, sinkName } from "../format";
import { useLoad } from "../useLoad";

const actionTitle: Record<string, string> = {
  revoke_session: "Revoked a session",
  revoke_device: "Revoked admin rights on a Mac",
  approve_enrollment: "Approved an enrollment",
  revoke_enrollment: "Revoked an enrollment",
  change_settings: "Changed settings",
  sign_in: "Signed in",
  sign_out: "Signed out",
  test_export: "Sent a SIEM test event",
  retry_exports: "Retried SIEM exports now",
  end_console_session: "Ended someone's console sign-in",
  remove_device: "Removed a Mac",
  expire_history: "Removed old history",
};

/** A person's email with single sign-on; otherwise which token, by fingerprint. The server
 *  itself, when it acted without anyone asking (it removed a Mac or old history), is Altiward. */
export function actorLabel(actor: string): string {
  if (actor === "altiward:server") return "Altiward";
  if (actor.startsWith("token:")) return `Console token ${actor.slice("token:".length)}`;
  if (actor.startsWith("break-glass:")) return `Break-glass token ${actor.slice("break-glass:".length)}`;
  return actor;
}

const str = (v: unknown) => (typeof v === "string" && v ? v : null);

/** What the action was about, in words. */
export function auditSummary(a: AuditEntry): string {
  const d = a.detail;
  switch (a.action) {
    case "revoke_session":
      return `${str(d.user) ?? "A user"} on ${str(d.serial) ?? "a Mac"}`;
    case "revoke_device":
      return `${str(d.user) ?? "Everyone but permanent admins"} on ${str(d.serial) ?? a.target}`;
    case "approve_enrollment":
    case "revoke_enrollment":
      return str(d.serial) ?? a.target;
    case "change_settings":
      return settingsChange(d.previous, d.settings);
    case "sign_in":
      return `Single sign-on${str(d.role) ? ` as ${str(d.role)}` : ""}`;
    case "sign_out":
      return "Single sign-on";
    case "test_export":
      return Array.isArray(d.sinks) ? d.sinks.map((s) => sinkName(String(s))).join(" and ") : "SIEM";
    case "retry_exports":
      return sinkName(a.target);
    case "remove_device":
      return str(d.serial) ?? a.target;
    case "expire_history":
      return removedCounts(d.counts);
    case "end_console_session":
      return str(d.name) ? `${str(d.name)} (${a.target})` : a.target;
  }
  return a.target;
}

/** How much an expire_history run removed: Macs only when it removed any, as the SIEM's
 *  message says it. */
function removedCounts(counts: unknown): string {
  const c = (counts ?? {}) as Record<string, unknown>;
  const n = (k: string) => (typeof c[k] === "number" ? c[k] as number : 0);
  const count = (k: string, one: string, many: string) => `${n(k).toLocaleString()} ${n(k) === 1 ? one : many}`;
  return [
    count("events", "event", "events"),
    count("sessions", "session", "sessions"),
    count("commands", "command", "commands"),
    ...(n("macs") ? [count("macs", "Mac", "Macs")] : []),
  ].join(", ");
}

const settingNames: Record<string, string> = {
  reenrollment_requires_approval: "Approve Macs that enrol again",
  new_mac_requires_approval: "Approve every new Mac",
  silent_after_hours: "Alert after hours without a check-in",
  history_days: "Keep history for",
};

/** A setting's value in words, where its number alone would read wrong. */
const settingValues: Record<string, (v: unknown) => string | null> = {
  history_days: (v) => (v === 0 ? "default" : v === -1 ? "for good" : typeof v === "number" ? `${v.toLocaleString()} days` : null),
};

/** Switches stored the other way round from how the console shows them. */
const invertedSettings: Record<string, string> = {
  silent_alerts_off: "Alert when a Mac stops checking in",
};

function settingsChange(before: unknown, after: unknown): string {
  const b = (before ?? {}) as Record<string, unknown>;
  const a = (after ?? {}) as Record<string, unknown>;
  const show = (v: unknown, k?: string) => (k && settingValues[k]?.(v))
    ?? (v === true ? "on" : v === false ? "off" : v === 0 ? "default" : String(v));
  // A setting added later is missing from older entries' previous values: its default then.
  const was = (k: string) => b[k] ?? (typeof a[k] === "number" ? 0 : false);
  const changes = Object.keys(a)
    .filter((k) => was(k) !== a[k])
    .map((k) => invertedSettings[k]
      ? `${invertedSettings[k]}: ${show(!was(k))} → ${show(!a[k])}`
      : `${settingNames[k] ?? k}: ${show(was(k), k)} → ${show(a[k], k)}`);
  return changes.join("; ") || "No change";
}

/** Who did what in the console, newest first. */
export function ActivityView() {
  const api = useApi();
  const { data, error, reload } = useLoad(() => api.audit({ limit: 500 }), [], 30_000);

  return (
    <>
      <Toolbar title="Activity" subtitle={data ? "Sign-ins and changes made in the console, newest first" : undefined} onRefresh={reload} />
      <div className="split">
        <div className="pane">
          {error && <Banner>{error}</Banner>}
          {data && data.length === 0 ? (
            <Empty title="No activity yet">Sign-ins, revokes, enrollment decisions and settings changes appear here.</Empty>
          ) : (
            <Table label="Activity" rows={data ?? []} rowKey={(a) => a.id} initialSort={{ key: "at", descending: true }}
              columns={[
                { key: "at", title: "When", sort: (a) => new Date(a.at).getTime(),
                  render: (a) => <span className="secondary small">{dateTime(a.at)}</span> },
                { key: "action", title: "Action", sort: (a) => actionTitle[a.action] ?? a.action,
                  render: (a) => actionTitle[a.action] ?? a.action },
                { key: "about", title: "Details", render: (a) => <span title={auditSummary(a)}>{auditSummary(a)}</span> },
                { key: "actor", title: "By", sort: (a) => a.actor, render: (a) => <span className="data">{actorLabel(a.actor)}</span> },
              ]} />
          )}
        </div>
      </div>
    </>
  );
}
