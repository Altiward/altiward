// Fills a local API (`make run-api`) with realistic demo data through the real agent
// protocol: each fake Mac enrolls with its own P-256 key and signs its events.
// Development only. Usage: node dev/seed.mjs [http://127.0.0.1:8080]
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";

const server = process.argv[2] ?? "http://127.0.0.1:8080";
const ENROLL = "dev-agent-token-0001";
const CONSOLE = "dev-console-token-001";
const now = Date.now();
const ago = (min) => new Date(now - min * 60_000).toISOString();

async function request(method, path, { bearer, body, mac } = {}) {
  const raw = body === undefined ? "" : JSON.stringify(body);
  const headers = { "Content-Type": "application/json" };
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (mac) {
    const ts = Math.floor(Date.now() / 1000);
    const digest = createHash("sha256").update(raw).digest("hex");
    const canonical = ["ALTIWARD-SIG-V1", method, path, ts, digest].join("\n");
    headers.Authorization = `AltiwardDevice ${mac.deviceID}`;
    headers["X-Altiward-Timestamp"] = String(ts);
    headers["X-Altiward-Signature"] = sign("sha256", Buffer.from(canonical), { key: mac.privateKey, dsaEncoding: "der" }).toString("base64");
  }
  const res = await fetch(server + path, { method, headers, body: raw || undefined });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text}`);
  return text ? JSON.parse(text) : {};
}

async function enroll(serial) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const r = await request("POST", "/v1/agent/enroll", {
    bearer: ENROLL, body: { serial, hardware_uuid: randomUUID().toUpperCase(), public_key: spki },
  });
  return { serial, deviceID: r.device_id, status: r.status, privateKey };
}

function event(mac, type, at, { user, session, elevation, detail = {} } = {}) {
  return {
    schema_version: 1, event_id: randomUUID(), type, session_id: session ?? null, timestamp: at,
    device: { serial: mac.serial, hardware_uuid: "HW-" + mac.serial, os_version: "26.1.0", agent_version: "0.1.0", privileges_version: "2.5.3" },
    user: user ? { local_name: user[0], upn: user[1] ?? null } : null,
    elevation: elevation ?? null, delayed: false, detail,
  };
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

// Re-running enrolls the same serials again; without this they would all wait for approval.
await request("PUT", "/v1/settings", { bearer: CONSOLE, body: { reenrollment_requires_approval: false } });
const [a, b, c, d, e, f] = await Promise.all(
  ["C02XK0AAJGH5", "C02VJ4EEMD6R", "C02ZM1BBMD6T", "C02YH2CCJG5H", "C02WQ3DDKL7M", "C02TN5FFHV2P"].map(enroll));

const s1 = randomUUID();
await send(a, [grant(a, jane, 12, 20, "Installing Xcode command line tools", s1), health(a, 2, ["itadmin", "jdoe"])]);

const s2 = randomUUID();
await send(b, [event(b, "admin.out_of_band", ago(130), { user: ["contractor"], session: s2,
  elevation: { reason: null, expires: null, source: "out_of_band" }, detail: { first_observed: ago(130) } }),
  health(b, 3, ["contractor", "itadmin"])]);

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
// the stored device in `make db`'s Postgres to match.
await send(f, [health(f, 4 * 24 * 60, ["itadmin"])]);
const silent = backdate(f.serial, ago(4 * 24 * 60));

/** Sets a device's server-side check-in time, so the silence monitor sees it as quiet. */
function backdate(serial, at) {
  const sql = `UPDATE devices SET last_seen_at = '${at}',
    state = jsonb_set(state, '{last_received_at}', to_jsonb('${at}'::text)) WHERE serial = '${serial}'`;
  try {
    execFileSync("docker", ["compose", "-f", new URL("compose.yaml", import.meta.url).pathname,
      "exec", "-T", "postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "altiward", "-d", "altiward", "-c", sql],
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
console.log(`Seeded 6 Macs (${silent ? 1 : 0} silent), 5 sessions, 1 tamper alert, 1 queued revoke; ${a.serial} re-enrolled (${again.status}).`);
console.log("Re-enrollment approval is now on; turn it off in Settings if you prefer.");
