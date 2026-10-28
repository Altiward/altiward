import { vi } from "vitest";
import type { Api, Enrollment, MDMDevice, MDMStatus, Me, Overview, Role, Session } from "../api";
import type { GitHubRelease } from "../updates";

export function session(over: Partial<Session> = {}): Session {
  return {
    session_id: "s-open", device_serial: "C02XK0AAJGH5", local_user: "jdoe", upn: "jane.doe@example.com",
    source: "privileges", reason: "Installing Xcode command line tools",
    started_at: "2026-10-16T09:14:03Z", expires_at: "2026-10-16T09:34:03Z", ended_at: null, end_reason: null,
    renewals: 0, verified: true, flags: [], event_count: 1, last_event_at: "2026-10-16T09:14:03Z",
    open: true, allowed_seconds: 1200, actual_seconds: 600, overran: false, permanent_admin: false, ...over,
  };
}

/** An active enrollment whose key is in the Secure Enclave. */
export function enrollment(over: Partial<Enrollment> = {}): Enrollment {
  return {
    device_id: "d-active", serial: "C02XK0AAJGH5", hardware_uuid: "HW-1", public_key: btoa("abc"),
    key_storage: "secure_enclave", token: "token:1a2b3c4d", status: "active", created_at: "2026-10-01T00:00:00Z",
    activated_at: "2026-10-01T00:00:00Z", revoked_at: null, ...over,
  };
}

/** Intune connected and synced a few minutes ago, with no keys checked yet. */
export function mdmStatus(over: Partial<MDMStatus> = {}): MDMStatus {
  return {
    configured: true, source: "intune", last_success_at: "2026-10-18T11:45:00Z", last_error: "", devices: 3,
    silence_held: 0, checks: {}, ...over,
  };
}

/** A Mac in the copy of Intune's devices. */
export function mdmDevice(over: Partial<MDMDevice> = {}): MDMDevice {
  return {
    serial: "C02XK0AAJGH5", primary_upn: "jane.doe@example.com", name: "Jane's MacBook Pro",
    last_check_in: "2026-10-18T10:00:00Z", ...over,
  };
}

/** An overview of a quiet fleet: one Mac, nothing held, nothing to look at. */
export function overview(over: Partial<Overview> = {}): Overview {
  const day = (i: number) => new Date(Date.UTC(2026, 9, 12 + i)).toISOString();
  return {
    generated_at: "2026-10-18T12:00:00Z", days: 7, since: "2026-10-11T12:00:00Z",
    now: { admins: 0, privileges: 0, without_grant: 0, past_expiry: 0, macs_failing_checks: 0, macs_silent: 0 },
    period: {
      elevations: 0, without_grant: 0, bucket_days: 1,
      buckets: Array.from({ length: 7 }, (_, i) => ({ start: day(i), privileges: 0, without_grant: 0 })),
      durations: [
        { source: "privileges", ended: 0, given_back_early: 0, median_held_seconds: null, median_allowed_seconds: null },
      ],
      top_users: [], top_macs: [],
    },
    health: { macs: 1, agents_outdated: 0, agent_versions: [{ version: "0.1.2", macs: 1, supported: true }], sinks: [] },
    ...over,
  };
}

/** An Api whose every method is a mock; tests override what they need. */
export function fakeApi(over: Partial<Api> = {}): Api {
  const none = () => vi.fn(async () => { throw new Error("not stubbed"); });
  return {
    sessions: vi.fn(async () => []), session: none(), devices: vi.fn(async () => []), overview: vi.fn(async () => overview()),
    enrollments: vi.fn(async () => []), approveEnrollment: none(), revokeEnrollment: none(),
    settings: vi.fn(async () => ({
      reenrollment_requires_approval: false, new_mac_requires_approval: false, silent_after_hours: 0, silent_alerts_off: false,
    })), putSettings: none(),
    revokeSession: none(), revokeDevice: none(), command: none(), commands: vi.fn(async () => []), audit: vi.fn(async () => []),
    about: vi.fn(async () => ({ version: "0.1.0", oldest_supported_agent: "0.1", update_check: false })),
    retention: vi.fn(async () => ({
      history: { days: 365, kept_for_good: false, reason: "default_no_siem" as const, held_before: null, waiting_for_backfill: false },
    })),
    me: vi.fn(async () => signedIn("admin")), signOut: vi.fn(async () => undefined),
    // Intune is off unless a test connects it.
    mdmStatus: vi.fn(async () => ({ configured: false })), mdmDevices: vi.fn(async () => []),
    exports: vi.fn(async () => []), testExport: none(), retryExports: none(),
    consoleSessions: vi.fn(async () => []), endConsoleSession: none(),
    ...over,
  } as Api;
}

/** A person signed in through single sign-on with role. */
export function signedIn(role: Role): Me {
  return { actor: "jane.doe@example.com", name: "Jane Doe", role, method: "sso", csrf_token: "csrf-1" };
}

/** Release notes as the release workflows publish them: the CHANGELOG section. */
export function notes({ security = "None." }: { security?: string } = {}): string {
  return `### Upgrade order\n\nUpgrade the server first.\n\n### Breaking changes\n\nNone.\n\n` +
    `### Security\n\n${security}\n\n### Changes\n\n- Faster.\n`;
}

export function release(tag: string, over: Partial<GitHubRelease> = {}): GitHubRelease {
  const pkg = tag.startsWith("agent-v") ? [{ name: `Altiward-${tag.slice(7)}.pkg`,
    browser_download_url: `https://github.com/Altiward/altiward/releases/download/${tag}/Altiward-${tag.slice(7)}.pkg` }] : [];
  return {
    tag_name: tag, html_url: `https://github.com/Altiward/altiward/releases/tag/${tag}`, body: notes(),
    draft: false, prerelease: tag.includes("-rc."), published_at: "2026-11-02T10:00:00Z", assets: pkg, ...over,
  };
}

/** GitHub's release list, newest first, with both products and a release candidate. */
export function releases(): GitHubRelease[] {
  return [
    release("server-v0.4.0", { draft: true }),
    release("server-v0.3.0-rc.1"),
    release("agent-v0.2.0"),
    release("server-v0.2.0", { body: notes({ security: "- Console sign-in no longer accepts an expired session." }) }),
    release("server-v0.1.0"),
    release("agent-v0.1.0"),
  ];
}

/** Stands in for the browser's fetch: GitHub answers with `list`, or fails. */
export function githubFetch(list: GitHubRelease[] | "offline" | number = releases()) {
  const fetch = vi.fn(async (_url: string, _init?: RequestInit) => {
    if (list === "offline") throw new TypeError("Failed to fetch");
    if (typeof list === "number") return new Response(JSON.stringify({ message: "rate limited" }), { status: list });
    return new Response(JSON.stringify(list), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
