// Acts as one Mac against a running server, through everything in front of it: enrolls
// with its own key, sends one signed event, and holds one command long poll for its full
// 50 seconds. With a console token, it also finds the Mac in the console's device list.
// Run against a deployed server; for a local one, `make run-api` and its dev tokens.
//
//   node scripts/agent-smoke.mjs <server URL> <agent token> [console token]
//
// The tokens are the parts after "<organisation>=". Node's built-in modules only.
import { randomUUID } from "node:crypto";
import { agentClient, event } from "../dev/agent-client.mjs";

const [server, agentToken, consoleToken] = process.argv.slice(2);
if (!server || !agentToken) {
  console.error("usage: node scripts/agent-smoke.mjs <server URL> <agent token> [console token]");
  process.exit(2);
}
const { request, enroll } = agentClient(server.replace(/\/$/, ""), agentToken);
const ok = (what) => console.log(`ok - ${what}`);

const serial = "SMOKE" + randomUUID().replace(/-/g, "").slice(0, 7).toUpperCase();
const mac = await enroll(serial);
if (mac.status !== "active") throw new Error(`enrolled ${serial} as ${mac.status}, want active`);
ok(`enrolled ${serial}`);

const health = event(mac, "agent.health", new Date().toISOString(), { detail: {
  integrity: { code_signature: true, launch_daemon: true, privileges_hook: true,
    privileges_tamper_protection: true, settings_managed: true },
  admin_members: ["itadmin"], permanent_admins: ["itadmin"], open_sessions: [], queue_depth: 0,
  privileges: { installed: true, post_change_hook_configured: true, pass_reason_to_executable: true,
    expiration_interval_minutes: 20, expiration_interval_max_minutes: null, enforce_privileges: null, system_extension_enabled: true },
} });
const sent = await request("POST", "/v1/agent/events", { mac, body: { events: [health] } });
if (sent.accepted?.length !== 1) throw new Error(`event not accepted: ${JSON.stringify(sent)}`);
ok("sent a signed event");

// The agent holds this open so a revoke reaches it within about a second; whatever is in
// front of the server must let it run its full 50 seconds.
const started = Date.now();
const polled = await request("GET", "/v1/agent/commands?wait=50", { mac });
const held = (Date.now() - started) / 1000;
if (!Array.isArray(polled.commands) || held < 45) {
  throw new Error(`long poll answered after ${held.toFixed(1)} s with ${JSON.stringify(polled)}`);
}
ok(`long poll held for ${held.toFixed(1)} s`);

if (consoleToken) {
  const { devices } = await request("GET", "/v1/devices", { bearer: consoleToken });
  if (!devices.some((d) => d.serial === serial)) throw new Error(`${serial} isn't in the console's devices`);
  ok(`the console lists ${serial}`);
}
