// Typed client for the Altiward API (backend/README.md). Field names follow the wire.

export interface Session {
  session_id: string;
  device_serial: string;
  local_user: string;
  upn: string | null;
  source: string;
  reason: string | null;
  started_at: string | null;
  expires_at: string | null;
  ended_at: string | null;
  end_reason: string | null;
  renewals: number;
  verified: boolean;
  flags: string[];
  event_count: number;
  last_event_at: string;
  open: boolean;
  allowed_seconds: number | null;
  actual_seconds: number | null;
  overran: boolean;
  /** The Mac's agent never demotes or revokes this user, so there is nothing to revoke. */
  permanent_admin: boolean;
}

export interface TimelineEvent {
  event_id: string;
  type: string;
  timestamp: string;
  received_at: string;
  delayed: boolean;
  user: { local_name: string; upn: string | null } | null;
  elevation: { reason: string | null; expires: string | null; source: string } | null;
  detail: Record<string, unknown>;
}

export interface Device {
  serial: string;
  hardware_uuid: string;
  os_version: string;
  agent_version: string;
  privileges_version: string | null;
  first_seen_at: string;
  /** Newest event, by the Mac's clock. */
  last_seen_at: string;
  last_health_at: string | null;
  /** When the server last heard from the Mac, by its own clock. Missing when unknown. */
  last_received_at?: string;
  admin_members: string[];
  /** Missing when unknown. */
  permanent_admins?: string[];
  queue_depth: number | null;
  privileges: Record<string, unknown> | null;
  /** Tamper checks from the newest health reading, check → passing. Missing or null until the agent reports them. */
  integrity?: Record<string, boolean> | null;
  /** Places the newest persistence snapshot couldn't read. Empty when it read them all; missing or null when unknown. */
  persistence_unreadable?: string[] | null;
  /** Newest first, at most 20. Missing or null when there are none. */
  recent_tamper?: TamperAlert[];
  /** Every open sign-in first (at most 20, newest first), then at most 20 ended and single
   *  uses, newest first by when each ended, else its last use, else when it began. Missing or
   *  null when none are recorded. */
  recent_permanent_uses?: PermanentUse[] | null;
  /** The newest agent.silent the server raised for this Mac; missing or null if none. */
  silence?: Silence | null;
  /** When an admin revoked the Mac's only key and none is waiting for approval; missing while the Mac is in use.
   *  Approving a key for the serial restores it, as does a stale-key contest. */
  retired_at?: string;
}

/** How long the server keeps history, from GET /v1/retention. `days` is 0 when nothing is removed. */
export interface HistoryPolicy {
  days: number;
  kept_for_good: boolean;
  reason: "default_siem" | "default_no_siem" | "set" | "kept_for_good";
  /** History before this is held back, as the SIEM hasn't had it yet; null when nothing is held. */
  held_before: string | null;
  waiting_for_backfill: boolean;
}

/** The server noticing a Mac stopped checking in (silent), or that it came back (resumed). */
export interface Silence {
  event_id: string;
  at: string;
  state: "silent" | "resumed";
  /** The Mac's last check-in when the server raised it. */
  last_seen_at: string;
}

/** A tamper check changing (agent.tamper): failed, restored, retired (a failing check that
 *  stopped applying), or a one-off detected. */
export interface TamperAlert {
  event_id: string;
  at: string;
  check: string;
  state: "failed" | "restored" | "retired" | "detected";
  problem: string | null;
}

/** One use of a permanent admin account (admin.permanent_use). A sign-in is one entry,
 *  started until ended; a prompt, sudo or su is a single. */
export interface PermanentUse {
  use_id: string;
  account: string;
  /** console, terminal, ssh, screen_sharing, prompt, sudo or su; a later agent may send others. */
  method: string;
  state: "started" | "ended" | "single";
  started_at: string;
  ended_at: string | null;
  /** The newest use grouped into a single; missing or null otherwise. */
  last_at?: string | null;
  /** The user whose session it was, for a prompt or su; null when unknown. */
  on_session_of: string | null;
  remote_host: string | null;
  /** The authorisation right a prompt approved. */
  right: string | null;
  /** The user a sudo ran as; missing or null when unknown. */
  run_as?: string | null;
  /** Single uses grouped into this entry; 1 for a sign-in. */
  count: number;
}

export type CredentialStatus = "active" | "pending" | "revoked";
/** Where the Mac said its key is kept when it enrolled; empty from agents before 0.2.0. */
export type KeyStorage = "secure_enclave" | "software" | "";

/** What Intune said about the device ID a Mac sent as it enrolled. */
export type MDMCheck = "not_sent" | "invalid_id" | "match" | "mismatch" | "unknown_id" | "unavailable";

export interface Enrollment {
  device_id: string;
  serial: string;
  hardware_uuid: string;
  public_key: string;
  key_storage: KeyStorage;
  /** The enrolling token's fingerprint, "token:" and 8 hex digits; empty before server 0.9.0. */
  token: string;
  status: CredentialStatus;
  created_at: string;
  activated_at: string | null;
  revoked_at: string | null;
  /** The key this one replaced by rotation; missing for an enrolled key. */
  rotated_from?: string;
  /** The key that replaced this one by rotation; present on a stale key, which is revoked. */
  rotated_to?: string;
  /** Intune's check of the device ID the Mac sent when it enrolled; missing when Intune was off or the key predates the check.
   *  The ID itself is never in the API. */
  mdm_check?: MDMCheck;
}

export interface CommandResult {
  status: "completed" | "failed" | "skipped";
  error: string | null;
  revoked: string[];
  failed: { user: string; error: string }[];
  skipped: { user: string; reason: string }[];
  completed_at: string;
}

export interface Command {
  command_id: string;
  serial: string;
  type: string;
  user: string | null;
  session_id: string | null;
  issued_by: string;
  created_at: string;
  expires_at: string;
  delivered_at: string | null;
  result_at: string | null;
  result: CommandResult | null;
  status: "pending" | "completed" | "failed" | "skipped" | "expired";
}

export interface Settings {
  reenrollment_requires_approval: boolean;
  /** A Mac's first key waits for approval too; off unless an admin turns it on, and when missing. */
  new_mac_requires_approval?: boolean;
  /** Hours without a check-in before the server raises agent.silent; 0 means the default, 72. */
  silent_after_hours: number;
  silent_alerts_off: boolean;
  /** How long history is kept: 0 the default, -1 for good, otherwise 90 to 3650 days. Left out, the stored value stays. */
  history_days?: number;
  /** A new key whose Intune check isn't a match waits for approval. Applies only while Intune is connected; off when missing. */
  require_intune_match?: boolean;
}

/** GET /v1/mdm: the Intune connection. Only `configured` is set while Intune is off. */
export interface MDMStatus {
  configured: boolean;
  source?: string;
  last_success_at?: string;
  last_error_at?: string;
  last_error?: string;
  /** Macs in the copy at the last success. */
  devices?: number;
  silence_held_at?: string;
  silence_held?: number;
  /** Keys in use by the outcome of their Intune check. An outcome never seen is left out: read it as 0. */
  checks?: Partial<Record<MDMCheck, number>>;
}

/** A Mac in the copy of what Intune manages. The IDs that identify it to Intune are never sent. */
export interface MDMDevice {
  serial: string;
  primary_upn: string;
  name: string;
  /** Missing when the Mac has never checked in with Intune. */
  last_check_in?: string;
}

/** One console action from the audit log. */
export interface AuditEntry {
  id: string;
  tenant_id: string;
  at: string;
  /** The person's email with single sign-on; otherwise "token:" or "break-glass:" and a console token's fingerprint.
   *  "altiward:server" for what the server did itself, such as removing a Mac or old history. */
  actor: string;
  action: "revoke_session" | "revoke_device" | "approve_enrollment" | "revoke_enrollment" | "change_settings"
    | "test_export" | "retry_exports" | "end_console_session" | "remove_device" | "expire_history" | string;
  target: string;
  detail: Record<string, unknown>;
  /** Orders entries recorded in the same instant; with `at`, the cursor for the next page. */
  seq: number;
}

/** One SIEM export sink's queue for this tenant. The sinks are set in the server's .env. */
export interface ExportSink {
  sink: "splunk" | "sentinel" | "syslog" | string;
  /** Events and console actions waiting to be sent. */
  pending: number;
  /** Of those, how many have failed at least once. */
  failing: number;
  oldest_queued_at: string | null;
  max_attempts: number;
  last_error?: string;
  /** When this SIEM last accepted something from this server; null for never. */
  last_delivered_at: string | null;
}

/** The overview's period, in days. */
export type OverviewDays = 7 | 30 | 90;

/** GET /v1/overview: worked out on the server from sessions, devices and SIEM queues. */
export interface Overview {
  generated_at: string;
  days: OverviewDays;
  since: string;
  /** Admins are counted per open session, as Admins now lists them. */
  now: {
    /** Every open session. */
    admins: number;
    privileges: number;
    without_grant: number;
    past_expiry: number;
    macs_failing_checks: number;
    macs_silent: number;
  };
  period: {
    elevations: number;
    without_grant: number;
    bucket_days: 1 | 7;
    buckets: { start: string; privileges: number; without_grant: number }[];
    durations: {
      source: "privileges";
      ended: number;
      given_back_early: number;
      median_held_seconds: number | null;
      median_allowed_seconds: number | null;
    }[];
    /** `serial` is set when `name` is a local account name rather than a UPN: one person per Mac. */
    top_users: { name: string; serial?: string; elevations: number; macs: number }[];
    top_macs: { serial: string; elevations: number; people: number }[];
  };
  health: {
    macs: number;
    agents_outdated: number;
    agent_versions: { version: string; macs: number; supported: boolean }[];
    sinks: (ExportSink & { state: "delivering" | "behind" | "failing" | "idle" })[];
  };
}

/** Someone signed in to the console through single sign-on. */
export interface ConsoleSignIn {
  /** Names the sign-in for ending it; not a credential. */
  id: string;
  actor: string;
  name: string;
  role: Role;
  created_at: string;
  /** When it ends however busy it is. */
  ends_at: string;
  /** When it ends if unused. */
  expires_at: string;
  /** The sign-in making this request. */
  current: boolean;
}

/** What a console caller may do. Each role includes the ones before it. */
export type Role = "viewer" | "operator" | "admin";

const roleRank: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

/** Whether `role` includes `need`. */
export const can = (role: Role | undefined, need: Role) => !!role && roleRank[role] >= roleRank[need];

/** Who is signed in: a person through single sign-on, or a console token. */
export interface Me {
  /** Their email, or "token:"/"break-glass:" and a token's fingerprint. */
  actor: string;
  name: string;
  role: Role;
  method: "sso" | "token";
  /** Single sign-on only: sent back with every change. */
  csrf_token?: string;
  ends_at?: string;
}

/** How the console authenticates: a pasted console token, or the session cookie single sign-on set. */
export type Credentials = { token: string } | { csrf: string };

/** The server's version, the oldest agent minor release it accepts, and whether the update check is on. */
export interface About {
  version: string;
  oldest_supported_agent: string;
  /** The severity each known tamper check's failure is exported with: check → "High", "Medium"… */
  tamper_severities?: Record<string, string>;
  /** Whether the console may ask GitHub for newer releases (ALTIWARD_UPDATE_CHECK); missing from older servers. */
  update_check?: boolean;
  /** Set when the server runs somewhere that changes how to upgrade it: Azure Container Apps, as the named app. */
  platform?: "azure-container-apps";
  app?: string;
}

/** What a refusal carries besides its message. */
export interface ApiErrorBody {
  code?: string;
  /** With "credential_rotated": the key in use, which is the one to revoke. */
  current_device_id?: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body: ApiErrorBody = {},
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface Options {
  fetch?: (url: string, init?: RequestInit) => Promise<Response>;
  onUnauthorized?: () => void;
}

type Query = Record<string, string | number | boolean | undefined>;

export function createApi(credentials: Credentials, { fetch: fetchImpl = (u, i) => fetch(u, i), onUnauthorized }: Options = {}) {
  async function call<T>(method: string, path: string, query?: Query, body?: unknown): Promise<T> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== "") params.set(k, String(v));
    const url = params.size ? `${path}?${params}` : path;
    const headers: Record<string, string> = {};
    if ("token" in credentials) headers.Authorization = `Bearer ${credentials.token}`;
    else if (method !== "GET") headers["X-CSRF-Token"] = credentials.csrf;
    if (body !== undefined) headers["Content-Type"] = "application/json";

    let res: Response;
    try {
      res = await fetchImpl(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
      throw new ApiError(0, "Can’t reach the Altiward server. Check your connection, then try again.");
    }
    if (res.status === 204) return undefined as T;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (res.status === 401) onUnauthorized?.();
      const { error, code, current_device_id } = data as { error?: string } & ApiErrorBody;
      throw new ApiError(res.status, error ?? `The server returned ${res.status}.`, { code, current_device_id });
    }
    return data as T;
  }

  const id = encodeURIComponent;
  return {
    sessions: (q: { open?: boolean; user?: string; device?: string; limit?: number } = {}) =>
      call<{ sessions: Session[] }>("GET", "/v1/sessions", q).then((r) => r.sessions),
    session: (sessionID: string) =>
      call<{ session: Session; events: TimelineEvent[] }>("GET", `/v1/sessions/${id(sessionID)}`),
    devices: () => call<{ devices: Device[] }>("GET", "/v1/devices").then((r) => r.devices),
    overview: (days: OverviewDays) => call<Overview>("GET", "/v1/overview", { days }),
    enrollments: (q: { status?: CredentialStatus; serial?: string } = {}) =>
      call<{ enrollments: Enrollment[] }>("GET", "/v1/enrollments", q).then((r) => r.enrollments),
    approveEnrollment: (deviceID: string) => call<Enrollment>("POST", `/v1/enrollments/${id(deviceID)}/approve`),
    revokeEnrollment: (deviceID: string) => call<Enrollment>("POST", `/v1/enrollments/${id(deviceID)}/revoke`),
    mdmStatus: () => call<MDMStatus>("GET", "/v1/mdm"),
    mdmDevices: () => call<{ devices: MDMDevice[] }>("GET", "/v1/mdm/devices").then((r) => r.devices),
    settings: () => call<Settings>("GET", "/v1/settings"),
    putSettings: (s: Settings) => call<Settings>("PUT", "/v1/settings", undefined, s),
    revokeSession: (sessionID: string) => call<Command>("POST", `/v1/sessions/${id(sessionID)}/revoke`),
    revokeDevice: (serial: string, user?: string) =>
      call<Command>("POST", `/v1/devices/${id(serial)}/revoke`, undefined, user ? { user } : {}),
    command: (commandID: string) => call<Command>("GET", `/v1/commands/${id(commandID)}`),
    commands: (q: { serial?: string; status?: string } = {}) =>
      call<{ commands: Command[] }>("GET", "/v1/commands", q).then((r) => r.commands),
    about: () => call<About>("GET", "/v1/about"),
    retention: () => call<{ history: HistoryPolicy }>("GET", "/v1/retention"),
    audit: (q: { before?: string; before_seq?: number; limit?: number } = {}) =>
      call<{ entries: AuditEntry[] }>("GET", "/v1/audit", q).then((r) => r.entries),
    exports: () => call<{ sinks: ExportSink[] }>("GET", "/v1/exports").then((r) => r.sinks),
    testExport: () => call<{ queued_for: string[] }>("POST", "/v1/exports/test"),
    retryExports: (sink: string) => call<{ retried: number }>("POST", `/v1/exports/${id(sink)}/retry`),
    consoleSessions: () => call<{ sessions: ConsoleSignIn[] }>("GET", "/v1/console-sessions").then((r) => r.sessions),
    endConsoleSession: (sessionID: string) => call<void>("DELETE", `/v1/console-sessions/${id(sessionID)}`),
    me: () => call<Me>("GET", "/v1/auth/me"),
    /** Ends the session. With provider sign-out on, the server also gives the identity provider's sign-out address. */
    signOut: () => call<{ provider_sign_out_url?: string } | undefined>("POST", "/v1/auth/logout"),
  };
}

/** Before signing in: whether single sign-on is on, and who the session cookie belongs to, if anyone. */
export async function probeSignIn(fetchImpl: (url: string, init?: RequestInit) => Promise<Response> = (u, i) => fetch(u, i)):
  Promise<{ sso: boolean; me: Me | null }> {
  const get = async <T>(path: string): Promise<T | null> => {
    try {
      const res = await fetchImpl(path, { method: "GET" });
      return res.ok ? ((await res.json()) as T) : null;
    } catch {
      return null;
    }
  };
  const config = await get<{ sso: boolean }>("/v1/auth/config");
  const sso = config?.sso ?? false;
  return { sso, me: sso ? await get<Me>("/v1/auth/me") : null };
}

export type Api = ReturnType<typeof createApi>;
