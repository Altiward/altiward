import { describe, expect, it } from "vitest";
import type { Command } from "./api";
import {
  agentOutdated, commandOutcome, dateTime, endReasonLabel, expiresAfter, flagLabel, formatDuration, gauge, integrityCheckLabel, lastCheckIn, permanentUseMethodLabel, persistenceLines, relativeTime, relativeTimeInWords, shortFingerprint, tamperStateLabel,
} from "./format";

// A missing value is a word that says why (#105).
describe("missing values", () => {
  it("a missing date says so, in the caller's words when it knows why", () => {
    expect(dateTime(null)).toBe("Unknown");
    expect(dateTime(undefined, "Not yet")).toBe("Not yet");
  });

  const command = (over: Partial<Command>): Command => ({
    command_id: "c1", serial: "C02XK0AAJGH5", type: "revoke_admin", user: "jdoe", session_id: null,
    issued_by: "admin", created_at: "2026-10-25T10:00:00Z", expires_at: "2026-10-26T10:00:00Z",
    delivered_at: null, result_at: null, result: null, status: "pending", ...over,
  });

  it("a command with no outcome yet says where it is", () => {
    expect(commandOutcome(command({}))).toBe("Waiting to be sent");
    expect(commandOutcome(command({ delivered_at: "2026-10-25T10:00:01Z" }))).toBe("Sent to the Mac");
  });

  it("a command that changed nothing says so", () => {
    const result = { status: "completed" as const, error: null, revoked: [], failed: [], skipped: [], completed_at: "2026-10-25T10:00:02Z" };
    expect(commandOutcome(command({ status: "completed", result }))).toBe("Nothing to do");
  });
});

describe("formatDuration", () => {
  it.each([
    [0, "0 s"],
    [45, "45 s"],
    [60, "1 min"],
    [12 * 60 + 29, "12 min"],
    [3600 + 5 * 60, "1 h 5 min"],
    [2 * 86400 + 3 * 3600, "2 d 3 h"],
  ])("%d seconds is %s", (s, want) => expect(formatDuration(s)).toBe(want));
});

describe("relativeTime", () => {
  const now = new Date("2026-10-16T12:00:00Z");
  it.each([
    ["2026-10-16T11:59:40Z", "Just now"],
    ["2026-10-16T11:57:00Z", "3 min ago"],
    ["2026-10-16T10:00:00Z", "2 h ago"],
    ["2026-10-14T12:00:00Z", "2 d ago"],
  ])("%s is %s", (iso, want) => expect(relativeTime(iso, now)).toBe(want));
});

describe("relativeTimeInWords", () => {
  const now = new Date("2026-10-16T12:00:00Z");
  it.each([
    ["2026-10-16T11:59:40Z", "just now"],
    ["2026-10-16T11:59:00Z", "1 minute ago"],
    ["2026-10-16T11:56:00Z", "4 minutes ago"],
    ["2026-10-16T11:00:00Z", "1 hour ago"],
    ["2026-10-16T10:00:00Z", "2 hours ago"],
    ["2026-10-15T12:00:00Z", "1 day ago"],
    ["2026-10-14T12:00:00Z", "2 days ago"],
  ])("%s is %s", (iso, want) => expect(relativeTimeInWords(iso, now)).toBe(want));
});

describe("lastCheckIn", () => {
  const mac = { last_seen_at: "2026-10-16T09:00:00Z", last_health_at: "2026-10-16T10:00:00Z", last_received_at: "2026-10-16T11:00:00Z" };
  it("prefers the server's clock, then the newest health reading, then the newest event", () => {
    expect(lastCheckIn(mac)).toBe("2026-10-16T11:00:00Z");
    expect(lastCheckIn({ ...mac, last_received_at: undefined })).toBe("2026-10-16T10:00:00Z");
    expect(lastCheckIn({ ...mac, last_received_at: undefined, last_health_at: null })).toBe("2026-10-16T09:00:00Z");
  });
});

describe("gauge", () => {
  it("places the ceiling at the allowed time with headroom", () => {
    expect(gauge(600, 1200)).toEqual({ fill: 0.4, ceiling: 0.8, overrun: false });
  });
  it("fills to the end and marks overrun when rights outlive the allowance", () => {
    expect(gauge(2400, 1200)).toEqual({ fill: 1, ceiling: 0.5, overrun: true });
  });
  it("has no ceiling when no expiry is known", () => {
    expect(gauge(600, null)).toEqual({ fill: null, ceiling: null, overrun: false });
  });
});

describe("labels", () => {
  it("names how a session ended in the person's terms", () => {
    expect(endReasonLabel(null)).toBe("Elevated");
    expect(endReasonLabel("remote_revoke")).toBe("Revoked from the console");
    expect(endReasonLabel("expired_enforced")).toBe("Removed at expiry");
    expect(endReasonLabel("permanent_admin")).toBe("Now a permanent admin");
    expect(endReasonLabel("privileges_grant")).toBe("Replaced by a Privileges grant");
    expect(endReasonLabel("out_of_band_removed")).toBe("Removed without a grant");
    expect(endReasonLabel("something_new")).toBe("Ended");
  });
  it("hides flags that repeat the end reason and names the rest", () => {
    expect(flagLabel("inferred_end")).toBeNull();
    expect(flagLabel("out_of_band")).toBe("Found without a grant");
    expect(flagLabel("after_out_of_band")).toBe("Followed rights without a grant");
    expect(flagLabel("brand_new_flag")).toBe("brand_new_flag");
  });
});

describe("shortFingerprint", () => {
  it("groups the first 16 hex digits of the key's SHA-256", async () => {
    // SHA-256("abc") = ba7816bf8f01cfea…
    const key = btoa("abc");
    expect(await shortFingerprint(key)).toBe("BA78 16BF 8F01 CFEA");
  });
});

describe("sessionState", () => {
  it("is Elevated only while admin is held, Without a grant for rights nobody granted, else Ended", async () => {
    const { sessionState } = await import("./format");
    expect(sessionState({ open: true, source: "privileges" })).toBe("elevated");
    expect(sessionState({ open: true, source: "out_of_band" })).toBe("not-granted");
    expect(sessionState({ open: false, source: "out_of_band" })).toBe("ended");
    expect(sessionState({ open: false, source: "privileges" })).toBe("ended");
  });
});

describe("sourceLabel", () => {
  it("names rights nobody granted the same way as the SIEM finding", async () => {
    const { sourceLabel } = await import("./format");
    expect(sourceLabel("out_of_band")).toBe("Without a grant");
    expect(sourceLabel("privileges")).toBe("Privileges");
    expect(sourceLabel("something_new")).toBe("something_new");
  });
});

describe("integrity labels", () => {
  it.each([
    ["launch_daemon", "Agent launch item"],
    ["settings_managed", "Settings from MDM"],
    ["privileges_hook", "Privileges reports to Altiward"],
    ["privileges_timer", "Privileges timer running"],
    ["privileges_blocked", "Privileges blocked tampering"],
    ["grant_confirmation", "Grant confirmation"],
    ["grant_claim", "Grant claim not confirmed"],
    ["privileges_expiry_cap", "Privileges expiry cap"],
    ["privileges_renewal", "Privileges renewals off"],
    ["privileges_give_back_hook", "Privileges reports give-backs"],
    ["privileges_revoke_exclusions", "Privileges spares permanent admins"],
    ["something_new", "Something new"],
  ])("%s is %s", (check, want) => expect(integrityCheckLabel(check)).toBe(want));

  it.each([
    ["failed", "agent_version", "Failed"],
    ["restored", "launch_daemon", "Fixed"],
    ["retired", "privileges_hook", "No longer checked"],
    ["detected", "agent_version", "Downgraded"],
    ["detected", "privileges_blocked", "Blocked"],
    ["detected", "grant_claim", "Not confirmed"],
    ["failed", "grant_confirmation", "Failed"],
    ["restored", "grant_confirmation", "Fixed"],
    ["retired", "grant_confirmation", "No longer checked"],
  ])("%s %s is %s", (state, check, want) => expect(tamperStateLabel(state, check)).toBe(want));
});

describe("agentOutdated", () => {
  it.each([
    ["0.1.9", "0.2", true],
    ["0.2.0", "0.2", false],
    ["0.10.0", "0.2", false],
    ["1.0.0", "0.9", false],
    ["0.9.0", "1.0", true],
    ["dev", "0.2", false],
    ["0.1.0", "x", false],
  ])("%s against %s → %s", (v, oldest, want) => {
    expect(agentOutdated(v, oldest)).toBe(want);
  });
});

describe("persistenceLines", () => {
  it("says what each finding is", () => {
    expect(persistenceLines({
      findings: [
        { kind: "launch_daemon", change: "added", path: "/Library/LaunchDaemons/com.example.updater.plist" },
        { kind: "launch_agent", change: "modified", path: "/Users/jdoe/Library/LaunchAgents/a.plist" },
        { kind: "sudoers", change: "added", path: "/etc/sudoers.d/jdoe", added_lines: ["jdoe ALL=(ALL) NOPASSWD: ALL"] },
        { kind: "ssh_authorized_key", change: "added", user: "root" },
        { kind: "local_account", change: "added", name: "support", uid: 499 },
        { kind: "local_account", change: "added", name: "breakglass", uid: 502, admin: true },
        { kind: "remote_access", change: "added", service: "screen_sharing" },
      ],
      truncated: 2,
    })).toEqual([
      "New LaunchDaemon /Library/LaunchDaemons/com.example.updater.plist",
      "Changed LaunchAgent /Users/jdoe/Library/LaunchAgents/a.plist",
      "New sudoers rules in /etc/sudoers.d/jdoe",
      "New SSH key for root",
      "New account support",
      "New admin account breakglass",
      "Screen Sharing turned on",
      "And 2 more not sent",
    ]);
  });

  it("copes with a detail it doesn't know", () => {
    expect(persistenceLines({})).toEqual([]);
    expect(persistenceLines({ findings: [{ kind: "cron" }], truncated: 0 })).toEqual(["New cron"]);
  });
});

describe("permanentUseMethodLabel", () => {
  it.each([
    ["console", "Signed in at the Mac"],
    ["terminal", "Signed in using Terminal"],
    ["ssh", "Signed in over SSH"],
    ["screen_sharing", "Shared the screen"],
    ["prompt", "Approved a prompt"],
    ["sudo", "Ran sudo"],
    ["su", "Switched user with su"],
    ["endpoint_security_exec", "endpoint_security_exec"],
  ])("%s is %s", (method, want) => expect(permanentUseMethodLabel(method)).toBe(want));
});

describe("expiresAfter", () => {
  it.each([
    [{ expiration_interval_minutes: 20, expiry_capped: true }, "20 min"],
    [{ expiration_interval_max_minutes: 60, expiry_capped: true }, "Up to 60 min"],
    // MDM set no expiry on purpose: a fixed 0 wins over any maximum.
    [{ expiration_interval_minutes: 0, expiration_interval_max_minutes: 60, expiry_capped: false }, "Never"],
    [{ expiration_interval_max_minutes: 60, expiry_capped: false }, "Up to 60 min, not set by MDM"],
    [{ expiry_capped: false }, "No cap"],
    // An older agent doesn't say whether MDM set it.
    [{ expiration_interval_max_minutes: 60 }, "Up to 60 min"],
    [{}, null],
  ])("%j is %s", (p, want) => expect(expiresAfter(p)).toBe(want));
});
