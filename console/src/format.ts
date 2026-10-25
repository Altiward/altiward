// Display helpers. Labels follow the brand book: sentence case, plain words.

import type { Command } from "./api";

export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  const min = Math.floor(s / 60);
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  if (h < 24) return min % 60 ? `${h} h ${min % 60} min` : `${h} h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d} d ${h % 24} h` : `${d} d`;
}

export function relativeTime(iso: string, now: Date = new Date()): string {
  const seconds = (now.getTime() - new Date(iso).getTime()) / 1000;
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export interface Gauge {
  fill: number | null; // 0…1 of the track; null when no allowance is known
  ceiling: number | null; // where the allowance ends on the track
  overrun: boolean;
}

/** Time used against time allowed. The track runs to 125% of the allowance so the
 *  ceiling mark sits inside it; an overrun fills the track and moves the ceiling left. */
export function gauge(actualSeconds: number, allowedSeconds: number | null): Gauge {
  if (allowedSeconds == null || allowedSeconds <= 0) return { fill: null, ceiling: null, overrun: false };
  const scale = Math.max(allowedSeconds * 1.25, actualSeconds);
  return {
    fill: round(actualSeconds / scale),
    ceiling: round(allowedSeconds / scale),
    overrun: actualSeconds > allowedSeconds,
  };
}

const round = (n: number) => Math.round(n * 1000) / 1000;

const endReasons: Record<string, string> = {
  revoked: "Ended in Privileges",
  inferred: "Ended, seen by the agent",
  expired_enforced: "Removed at expiry",
  remote_revoke: "Revoked from the console",
  permanent_admin: "Now a permanent admin",
  privileges_grant: "Replaced by a Privileges grant",
  out_of_band_removed: "Removed without a grant",
};

export function endReasonLabel(reason: string | null): string {
  if (reason == null) return "Elevated";
  return endReasons[reason] ?? "Ended";
}

const flags: Record<string, string | null> = {
  unverified_claim: "Claim didn’t match the admin group",
  orphan_revoke: "Revoke without a grant",
  out_of_band: "Found without a grant",
  inferred_end: null, // already said by the end reason
  overdue: "Past expiry",
  persistence_detected: "New persistence",
  after_out_of_band: "Followed rights without a grant",
};

export function flagLabel(flag: string): string | null {
  return flag in flags ? flags[flag] : flag;
}

const sources: Record<string, string> = { privileges: "Privileges", out_of_band: "Without a grant" };

/** Where a session's rights came from. */
export function sourceLabel(source: string): string {
  return sources[source] ?? source;
}

/** The brand's StateBadge states (design system › StateBadge). Elevated is only ever
 *  live admin; a past session is Ended, whatever its length. */
export type State = "elevated" | "verified" | "claimed" | "not-granted" | "ended";

export function sessionState(s: { open: boolean; source: string }): State {
  if (!s.open) return "ended";
  return s.source === "out_of_band" ? "not-granted" : "elevated";
}

/** First 64 bits of the public key's SHA-256, for comparing a pending key with the Mac. */
export async function shortFingerprint(base64Key: string): Promise<string> {
  const bytes = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = Array.from(digest.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return hex.match(/.{4}/g)!.join(" ");
}

const integrityChecks: Record<string, string> = {
  launch_daemon: "Agent launch item",
  code_signature: "App signature",
  settings_managed: "Settings from MDM",
  privileges_tamper_protection: "Privileges tamper protection",
  privileges_hook: "Privileges reports to Altiward",
  privileges_timer: "Privileges timer running",
  agent_version: "Agent version",
  privileges_blocked: "Privileges blocked tampering",
  grant_confirmation: "Grant confirmation",
  grant_claim: "Grant claim not confirmed",
};

/** Words for the agent's tamper checks, sentence case. */
export function integrityCheckLabel(check: string): string {
  if (integrityChecks[check]) return integrityChecks[check];
  const words = check.replaceAll("_", " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** What an agent.tamper event says happened. */
export function tamperStateLabel(state: string, check: string): string {
  if (state === "restored") return "Fixed";
  if (state === "retired") return "No longer checked";
  if (state === "detected") {
    if (check === "agent_version") return "Downgraded";
    if (check === "grant_claim") return "Not confirmed";
    return check === "privileges_blocked" ? "Blocked" : "Detected";
  }
  return "Failed";
}

const permanentUseMethods: Record<string, string> = {
  console: "Signed in at the Mac",
  terminal: "Signed in using Terminal",
  ssh: "Signed in over SSH",
  screen_sharing: "Shared the screen",
  prompt: "Approved a prompt",
  sudo: "Ran sudo",
  su: "Switched user with su",
};

/** How a permanent admin account was used (admin.permanent_use). A method this console
 *  doesn't know, from a newer agent, shows as the agent sent it. */
export function permanentUseMethodLabel(method: string): string {
  return permanentUseMethods[method] ?? method;
}

/** Whether agent version `version` ("X.Y.Z") is older than the minor release `oldest`
 *  ("X.Y"). A version that can't be read isn't flagged, as the server does. */
export function agentOutdated(version: string, oldest: string): boolean {
  const parse = (v: string) => {
    const m = /^(\d+)\.(\d+)(?:\.\d+)?$/.exec(v);
    return m ? [Number(m[1]), Number(m[2])] : null;
  };
  const v = parse(version), o = parse(oldest);
  if (!v || !o) return false;
  return v[0] < o[0] || (v[0] === o[0] && v[1] < o[1]);
}

/** One line per persistence.detected finding, sentence case. */
export function persistenceLines(detail: Record<string, unknown>): string[] {
  const findings = Array.isArray(detail.findings) ? detail.findings : [];
  const lines = findings.map((raw) => {
    const f = (raw ?? {}) as Record<string, unknown>;
    const s = (k: string) => (typeof f[k] === "string" ? (f[k] as string) : "");
    const change = f.change === "modified" ? "Changed" : "New";
    switch (s("kind")) {
      case "launch_daemon": return `${change} LaunchDaemon ${s("path")}`;
      case "launch_agent": return `${change} LaunchAgent ${s("path")}`;
      case "sudoers": return `${change} sudoers rules in ${s("path")}`;
      case "ssh_authorized_key": return `${change} SSH key for ${s("user")}`;
      case "local_account": return `${change} ${f.admin === true ? "admin account" : "account"} ${s("name")}`;
      case "remote_access":
        return `${s("service") === "screen_sharing" ? "Screen Sharing" : s("service") === "remote_login" ? "Remote Login" : s("service")} turned on`;
      default: return `${change} ${s("kind")}`;
    }
  });
  const more = typeof detail.truncated === "number" ? detail.truncated : 0;
  if (more > 0) lines.push(`And ${more} more not sent`);
  return lines;
}

const sinkNames: Record<string, string> = { splunk: "Splunk", sentinel: "Microsoft Sentinel", syslog: "Syslog" };

/** A SIEM export sink's name as people know it. */
export function sinkName(sink: string): string {
  return sinkNames[sink] ?? sink;
}

const skipReasons: Record<string, string> = {
  permanent_admin: "permanent admin", not_admin: "not an admin", session_ended: "session already ended",
};

/** What a Mac did with a command, for the Commands table and follow-up notices. */
export function commandOutcome(c: Command): string {
  const r = c.result;
  if (!r) return c.status === "expired" ? "The Mac didn’t check in within 24 hours." : c.delivered_at ? "Sent to the Mac" : "—";
  if (r.error) return r.error;
  const parts = [
    r.revoked.length ? `Removed ${r.revoked.join(", ")}` : "",
    ...r.failed.map((f) => `${f.user}: ${f.error}`),
    ...r.skipped.map((s) => `Kept ${s.user} (${skipReasons[s.reason] ?? s.reason})`),
  ].filter(Boolean);
  return parts.join(". ") || "—";
}

/** The notice for a revoke once its Mac has reported back. `who` names the one person it was for. */
export function revokeNotice(c: Command, who?: string): { kind: "error" | "info"; text: string } {
  switch (c.status) {
    case "completed":
      return { kind: "info", text: who ? `Admin rights removed from ${who} on ${c.serial}.` : `${c.serial} removed admin rights. ${commandOutcome(c)}.` };
    case "skipped":
      return { kind: "info", text: `${c.serial} had nothing to remove. ${commandOutcome(c)}` };
    case "failed":
      return { kind: "error", text: `${c.serial} couldn’t remove admin rights. ${commandOutcome(c)}` };
    default:
      return { kind: "error", text: `${c.serial} didn’t check in before the revoke expired.` };
  }
}
