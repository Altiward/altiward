// Fills a local API (`make run-api`) with realistic demo data through the real agent
// protocol: each fake Mac enrolls with its own P-256 key and signs its events.
// Development only. Usage: node dev/seed.mjs [http://127.0.0.1:8080]
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { agentClient, event } from "./agent-client.mjs";

const server = process.argv[2] ?? "http://127.0.0.1:8080";
const ENROLL = "dev-agent-token-0001";
const CONSOLE = "dev-console-token-001";
const now = Date.now();
const ago = (min) => new Date(now - min * 60_000).toISOString();
const { request, enroll } = agentClient(server, ENROLL);

/** Waits up to 30 seconds for the API, which may still be starting, then explains. */
async function waitForAPI() {
  for (let attempt = 1; ; attempt++) {
    try {
      if ((await fetch(server + "/healthz")).ok) return;
    } catch {}
    if (attempt === 15) {
      console.error(`Can't reach the API at ${server}. Start it with \`make run-api\` in another terminal, leave it running, and run this again.`);
      process.exit(1);
    }
    if (attempt === 1) console.log(`Waiting for the API at ${server}...`);
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

const privileges = (reason, expires) => ({ reason, expires, source: "privileges" });
const grant = (mac, user, at, minutes, reason, session) =>
  event(mac, "elevation.granted", ago(at), { user, session, elevation: privileges(reason, ago(at - minutes)),
    detail: { trigger: "hook", claimed_state: "admin", observed_admin: true, verified: true, renewed: false } });
const passing = { code_signature: true, launch_daemon: true, privileges_hook: true,
  privileges_tamper_protection: true, settings_managed: true };
const health = (mac, at, admins, integrity = passing) =>
  event(mac, "agent.health", ago(at), { detail: {
    integrity,
    admin_members: admins, permanent_admins: ["itadmin"], open_sessions: [], queue_depth: 0,
    privileges: { installed: true, post_change_hook_configured: true, pass_reason_to_executable: true,
      expiration_interval_minutes: 20, expiration_interval_max_minutes: null, enforce_privileges: null, system_extension_enabled: true },
  } });
const send = (mac, events) => request("POST", "/v1/agent/events", { mac, body: { events } });

const jane = ["jdoe", "jane.doe@example.com"], anna = ["asmith", "anna.smith@example.com"],
  ben = ["bwong", "ben.wong@example.com"], mia = ["mlee", "mia.lee@example.com"];

await waitForAPI();

// Re-running enrolls the same serials again; without this they would all wait for approval.
await request("PUT", "/v1/settings", { bearer: CONSOLE, body: { reenrollment_requires_approval: false } });
// Most keep their key in the Secure Enclave; one has a file key (an Intel Mac without a T2
// chip) and one runs an agent from before 0.2.0, which doesn't say.
const [a, b, c, d, e, f] = await Promise.all([
  ["C02XK0AAJGH5", "secure_enclave"], ["C02VJ4EEMD6R", "secure_enclave"], ["C02ZM1BBMD6T", "secure_enclave"],
  ["C02YH2CCJG5H", "secure_enclave"], ["C02WQ3DDKL7M", "software"], ["C02TN5FFHV2P", null],
].map(([serial, keyStorage]) => enroll(serial, { keyStorage })));
// The Mac without a reported key runs agent 0.2.1, older than the server supports.
f.agentVersion = "0.2.1";

const s1 = randomUUID();
await send(a, [grant(a, jane, 12, 20, "Installing Xcode command line tools", s1), health(a, 2, ["itadmin", "jdoe"])]);

// The permanent admin `itadmin` was used on the first Mac: a sign-in at the screen
// yesterday that has ended, a prompt it approved on Jane's session, and an SSH sign-in from
// 10.0.0.5 that is still open (agent 0.3.0's admin.permanent_use).
const yesterday = (hour) => { const at = new Date(now); at.setDate(at.getDate() - 1); at.setHours(hour, 0, 0, 0); return at.toISOString(); };
const itadmin = ["itadmin"];
const consoleUse = randomUUID();
await send(a, [
  event(a, "admin.permanent_use", yesterday(13), { user: itadmin, detail: {
    use_id: consoleUse, method: "console", state: "ended", source: "utmpx", started: yesterday(10),
    ended: yesterday(13), end_basis: "logged", tty: "console" } }),
  event(a, "admin.permanent_use", ago(95), { user: itadmin, detail: {
    use_id: randomUUID(), method: "prompt", state: "single", source: "unified_log", started: ago(95),
    on_session_of: jane[0], right: "com.apple.ServiceManagement.daemons.modify",
    client: "/System/Applications/System Settings.app", count: 1, last: ago(95) } }),
  event(a, "admin.permanent_use", ago(50), { user: itadmin, detail: {
    use_id: randomUUID(), method: "ssh", state: "started", source: "utmpx", started: ago(50),
    tty: "ttys003", remote_host: "10.0.0.5" } }),
]);

// Its Privileges profile still pins an older agent's hook, so Privileges skipped the hook
// and the grant shows up as admin rights without one.
const s2 = randomUUID();
await send(b, [event(b, "agent.tamper", ago(140), { detail: { check: "privileges_hook", state: "failed",
    problem: "PostChangeExecutableChecksum doesn't match Altiward's hook, so Privileges won't run it: " +
      "use the corp.sap.privileges.plist from this agent's release" } }),
  event(b, "admin.out_of_band", ago(130), { user: ["contractor"], session: s2,
    elevation: { reason: null, expires: null, source: "out_of_band" }, detail: { first_observed: ago(130) } }),
  health(b, 3, ["contractor", "itadmin"], { ...passing, privileges_hook: false })]);

const s3 = randomUUID();
await send(c, [grant(c, anna, 42, 20, "Updating a printer driver", s3),
  event(c, "elevation.overdue", ago(17), { user: anna, session: s3, elevation: privileges(null, ago(22)),
    detail: { trigger: "heartbeat", expired_at: ago(22), grace_seconds: 300, observed_admin: true, enforcement: "alert", enforcement_failed: false } }),
  health(c, 1, ["asmith", "itadmin"])]);

const s4 = randomUUID();
await send(d, [grant(d, ben, 190, 20, "Homebrew upgrade", s4),
  event(d, "elevation.revoked", ago(176), { user: ben, session: s4, elevation: privileges(null, null),
    detail: { trigger: "hook", claimed_state: "user", observed_admin: false, verified: true } }),
  health(d, 41, ["itadmin"])]);

// Later on the same Mac, someone made an account and added it to admin by hand. Privileges'
// system extension logged who did it, then blocked an attempt to move Privileges aside, and
// the account was revoked from the console.
const s6 = randomUUID(), backdoor = ["svc-backup"];
const dseditgroup = { executable: "/usr/sbin/dseditgroup", signing_id: "com.apple.dseditgroup", team_id: "",
  platform_binary: true, pid: 4127, ppid: 4120, tty: "/dev/ttys002" };
const outOfBand = { reason: null, expires: null, source: "out_of_band" };
await send(d, [event(d, "admin.out_of_band", ago(38), { user: backdoor, session: s6, elevation: outOfBand,
    detail: { first_observed: ago(38), instigator: { ...dseditgroup, logged_at: ago(38.5) } } }),
  event(d, "persistence.detected", ago(37.9), { user: backdoor, session: s6, elevation: outOfBand,
    detail: { since: ago(39), truncated: 0, findings: [
      { kind: "local_account", change: "added", name: "svc-backup", uid: 503, admin: true }] } }),
  event(d, "agent.tamper", ago(36), { detail: { check: "privileges_blocked", state: "detected",
    problem: "SAP Privileges blocked /bin/mv from trying to rename /Applications/Privileges.app",
    blocked_action: "RENAME", item: "/Applications/Privileges.app", attempts: 1,
    instigator: { ...dseditgroup, executable: "/bin/mv", signing_id: "com.apple.mv", pid: 4133 },
    first_attempt: ago(36.5), last_attempt: ago(36.5) } }),
  event(d, "elevation.revoked", ago(33), { user: backdoor, session: s6, elevation: outOfBand,
    detail: { trigger: "command", command_id: randomUUID(), observed_admin: false, verified: true } }),
  health(d, 2, ["itadmin"])]);

const s5 = randomUUID();
await send(e, [grant(e, mia, 1500, 60, "Configuring a VPN client", s5),
  event(e, "elevation.revoked", ago(1490), { user: mia, session: s5, elevation: privileges(null, null),
    detail: { trigger: "command", command_id: randomUUID(), observed_admin: false, verified: true } }),
  // Someone switched off Privileges' tamper protection on this Mac.
  event(e, "agent.tamper", ago(30), { detail: { check: "privileges_tamper_protection", state: "failed",
    problem: "Privileges' tamper protection (EnableSystemExtension) is off" } }),
  health(e, 4, ["itadmin"], { ...passing, privileges_tamper_protection: false })]);

// A Mac last heard from four days ago: within a minute the API's monitor raises agent.silent.
// Check-ins are timed by the server's clock, so the API records this one as now; backdate
// the stored device in `make db`'s Postgres to match. SEED_BACKDATE=external leaves that to
// the caller: compose.demo.yaml's seed container has no Docker CLI, so its ready service does it.
await send(f, [health(f, 4 * 24 * 60, ["itadmin"])]);
const silent = process.env.SEED_BACKDATE === "external" || backdate(f.serial, ago(4 * 24 * 60));

/** Sets a device's server-side check-in time, so the silence monitor sees it as quiet. */
function backdate(serial, at) {
  const sql = `UPDATE devices SET last_seen_at = '${at}',
    state = jsonb_set(state, '{last_received_at}', to_jsonb('${at}'::text)) WHERE serial = '${serial}'`;
  try {
    execFileSync("docker", ["compose", "-f", new URL("compose.yaml", import.meta.url).pathname,
      "exec", "-T", "postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "altiward",
      "-d", process.env.SEED_DATABASE ?? "altiward", "-c", sql],
    { stdio: ["ignore", "ignore", "pipe"] });
    return true;
  } catch (err) {
    console.warn(`Couldn't backdate ${serial} in make db's Postgres, so it won't go silent: ${err.stderr?.toString().trim() || err.message}`);
    return false;
  }
}

// A queued device-wide revoke, and a reinstalled Mac waiting for approval.
await request("POST", `/v1/devices/${b.serial}/revoke`, { bearer: CONSOLE, body: {} });
await request("PUT", "/v1/settings", { bearer: CONSOLE, body: { reenrollment_requires_approval: true } });
const again = await enroll(a.serial);
console.log(`Seeded 6 Macs (${silent ? 1 : 0} silent), 6 sessions, 3 tamper alerts, 3 uses of a permanent admin, 1 queued revoke; ${a.serial} re-enrolled (${again.status}).`);
console.log("Re-enrollment approval is now on; turn it off in Settings if you prefer.");
