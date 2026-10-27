// Fills a local API with the example organisation pictured on altiward.com, through the real
// agent protocol: 42 Macs, three months of elevations, and ten people with admin rights now,
// one of them past their expiry and one account without a grant. seed.mjs's smaller data
// set is the install guide's. A fixed random seed makes the same organisation every time;
// only the dates follow the clock.
// Development only. Usage: node dev/seed-site.mjs [http://127.0.0.1:8080]
// scripts/docs/site-screenshots.mjs imports it, and uses applyRevokes to act as a Mac.
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { agentClient, event } from "./agent-client.mjs";

const ENROLL = "dev-agent-token-0001";
const CONSOLE = "dev-console-token-001";
const MINUTE = 60_000, DAY = 24 * 60 * MINUTE;
/** Days of history, and the Overview's default period. */
const HISTORY_DAYS = 90, PERIOD_DAYS = 30;
/** Elevations in the Overview's 30 days, the account without a grant included. The Splunk
 *  dashboard illustration on altiward.com quotes this number. */
const IN_PERIOD = 255;

/** How long each team's Privileges profile grants admin rights for, in minutes. */
const teams = { engineering: 60, data: 30, office: 20, finance: 15 };

/** Everyone with a Mac: name, team and how often they need admin rights, relatively. */
const roster = [
  ["Hannah Lindqvist", "engineering", 5], ["Owen Park", "engineering", 4.5], ["Chloe Martin", "engineering", 4],
  ["Lukas Brandt", "engineering", 2.5], ["Mei Chen", "engineering", 2.5], ["Arjun Mehta", "engineering", 2],
  ["Samuel Osei", "engineering", 1.5], ["Yuki Tanaka", "engineering", 1.5],
  ["Kenji Watanabe", "data", 2.5], ["Tomas Duarte", "data", 2], ["Ravi Patel", "data", 1.5],
  ["Nina Kowalski", "data", 1.2], ["Isabel Cruz", "data", 1],
  ["Emma Novak", "office", 1.5], ["Priya Raman", "office", 1.8], ["Sofia Marchetti", "office", 1.2],
  ["Aisha Bello", "office", 1], ["Daniel Okafor", "office", 0.6], ["Laura Fischer", "office", 0.8],
  ["James Whitaker", "office", 0.5], ["Lucas Moreau", "office", 0.9], ["Ben Hughes", "office", 0.5],
  ["Fatima Rahman", "office", 0.7], ["Grace Adeyemi", "office", 0.8], ["Tom Fletcher", "office", 0.4],
  ["Elena Rossi", "office", 0.9], ["Ahmed Khalil", "office", 0.6], ["Rachel Stein", "office", 0.7],
  ["Zoe Campbell", "office", 0.5], ["Jonas Lindgren", "office", 0.6], ["Maya Goldberg", "office", 0.8],
  ["Callum Reid", "office", 0.4], ["Leah Morgan", "office", 0.6], ["Patrick Doyle", "office", 0.4],
  ["Hugo Lambert", "office", 0.5],
  ["Marcus Webb", "finance", 0.8], ["Sarah Collins", "finance", 0.5], ["David Ng", "finance", 0.4],
];

/** Who holds admin rights now: minutes since the grant, and the reason given. */
const elevatedNow = [
  ["Emma Novak", 41, "Installing a scanner driver"], ["Chloe Martin", 38, "Debugging a launch daemon"],
  ["Hannah Lindqvist", 22, "Rebuilding the local development environment"], ["Kenji Watanabe", 17, "Installing Python 3.13"],
  ["Aisha Bello", 14, "Updating a printer driver"], ["Tomas Duarte", 11, "Installing Wireshark"],
  ["Sofia Marchetti", 9, "Installing the brand fonts"], ["Priya Raman", 6, "Configuring a VPN client"],
  ["Marcus Webb", 4, "Installing a card reader driver"],
];

/** Reasons people give, by team. Some are as terse as people type them. */
const reasons = {
  engineering: ["Installing Xcode command line tools", "Updating Homebrew", "brew upgrade", "Installing Docker Desktop",
    "Updating Node.js", "Debugging a launch daemon", "Installing a code signing certificate", "Editing /etc/hosts",
    "Installing Android Studio", "Changing the firewall settings", "xcode-select", "Installing a Java runtime",
    "Updating Docker Desktop", "Running a local server on port 443"],
  data: ["Installing Python 3.13", "Installing R and RStudio", "Updating Tableau Desktop", "Installing an ODBC driver",
    "Installing Wireshark", "Updating Homebrew", "Installing a database driver", "pip install"],
  office: ["Installing a printer driver", "Updating a printer driver", "Configuring a VPN client", "Installing a font family",
    "Updating Zoom", "Installing a USB-C dock driver", "Installing Logi Options+", "Adding a Wi-Fi profile",
    "Installing a scanner driver", "Installing Adobe Acrobat", "printer", "Installing Microsoft Teams"],
  finance: ["Installing a card reader driver", "Updating an Excel add-in", "Installing a printer driver", "Configuring a VPN client"],
};

/** The same pseudo-random sequence every run (mulberry32). */
function random(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Times on a London calendar day, which the console shows them in. */
const london = new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/London", year: "numeric", month: "numeric",
  day: "numeric", hour: "numeric", minute: "numeric", hourCycle: "h23" });
function londonParts(ms) {
  const p = Object.fromEntries(london.formatToParts(new Date(ms)).map((x) => [x.type, Number(x.value)]));
  return { ...p, offset: Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute) - Math.floor(ms / MINUTE) * MINUTE };
}

/**
 * Seeds the organisation. `database` is the one the API uses in `make db`'s Postgres, for
 * the check-in times only psql can set. Returns the serials of the contractor's Mac and of
 * the Mac where Privileges blocked tampering, and applyRevokes(serial), which answers the
 * console's revokes for a Mac as its agent would.
 */
export async function seedSite(server, { database = process.env.SEED_DATABASE ?? "altiward" } = {}) {
  const rand = random(20261027);
  const pick = (list) => list[Math.floor(rand() * list.length)];
  const now = Date.now();
  const iso = (ms) => new Date(ms).toISOString();
  const ago = (min) => now - min * MINUTE;
  const { request, enroll } = agentClient(server, ENROLL);
  const today = londonParts(now);
  /** A London time of day, `back` calendar days before today. */
  const at = (back, minuteOfDay) => {
    const guess = Date.UTC(today.year, today.month - 1, today.day - back, 0, minuteOfDay);
    return guess - londonParts(guess).offset;
  };
  const weekday = (back) => new Date(Date.UTC(today.year, today.month - 1, today.day - back)).getUTCDay();

  // Apple silicon serials are ten random characters; the Intel Macs keep the older kind.
  const serial = () => Array.from({ length: 10 }, () => pick("0123456789BCDFGHJKLMNPQRSTVWXYZ")).join("");
  const people = roster.map(([name, team, weight]) => {
    const [first, last] = name.toLowerCase().split(" ");
    return { name, team, weight, user: [first[0] + last, `${first}.${last}@example.com`] };
  });
  const person = (name) => people.find((p) => p.name === name);
  const mac = (fields) => ({ serial: serial(), os: rand() < 0.75 ? "26.1.0" : rand() < 0.6 ? "26.0.1" : "15.7.2", ...fields });
  const macs = people.map((p) => mac({ owner: p }));
  // Special cases, with serials picked so that Fleet, sorted by serial, shows the outdated
  // agent on its first screen and leaves the Mac failing a check below it.
  macs.push(mac({ owner: person("Owen Park"), second: true }));
  Object.assign(macs[people.indexOf(person("Ben Hughes"))], { serial: "C02YH2CCJG5H", os: "26.1.0" });
  Object.assign(macs[people.indexOf(person("Emma Novak"))], { serial: "XC9R4WHN2K" });
  Object.assign(macs[people.indexOf(person("Laura Fischer"))], { serial: "C02DW4L8MD6M", os: "15.7.2" });
  const contractor = mac({ serial: "C02MVEHQGKMQ", os: "15.7.2", team: "office" });
  // Shared Macs nobody elevates on; the lab Mac missed the agent 1.0 rollout.
  const lab = mac({ serial: "C02FK2RNQ05D", os: "15.7.2", agentVersion: "0.9.0", team: "office" });
  const build = mac({ team: "engineering" });
  macs.push(contractor, lab, build);
  for (const m of macs) m.team ??= m.owner.team;

  // event() with this Mac's macOS.
  const ev = (m, type, ms, fields) => {
    const e = event(m, type, iso(ms), fields);
    e.device.os_version = m.os;
    return e;
  };
  const events = new Map(macs.map((m) => [m.serial, []]));
  const add = (m, e) => events.get(m.serial).push(e);
  const busy = new Map(macs.map((m) => [m.serial, []]));
  const free = (m, start, end) => !busy.get(m.serial).some(([s, e]) => start < e + 5 * MINUTE && end > s - 5 * MINUTE);
  const open = new Map(); // serial → sessions open now
  let inPeriod = 0;
  const since = now - PERIOD_DAYS * DAY;

  /** A Privileges grant, and its give-back unless `end` is null. */
  function session(m, who, start, end, reason) {
    const id = randomUUID(), allowed = teams[m.team];
    busy.get(m.serial).push([start, end ?? now]);
    add(m, ev(m, "elevation.granted", start, { user: who.user, session: id,
      elevation: { reason, expires: iso(start + allowed * MINUTE), source: "privileges" },
      detail: { trigger: "hook", claimed_state: "admin", observed_admin: true, verified: true, renewed: false,
        expires_basis: "ExpirationInterval", caller_uid: 501 } }));
    if (end != null) {
      add(m, ev(m, "elevation.revoked", end, { user: who.user, session: id,
        elevation: { reason: null, expires: null, source: "privileges" },
        detail: { claimed_state: "user", observed_admin: false, verified: true, trigger: "hook" } }));
    }
    if (start >= since) inPeriod++;
    return id;
  }

  /** Someone's elevation on `back` days ago: mostly given back early, sometimes held to expiry. */
  function past(back, latest = 17 * 60 + 30) {
    const total = people.reduce((sum, p) => sum + p.weight, 0);
    for (let tries = 0; tries < 50; tries++) {
      let r = rand() * total;
      const who = people.find((p) => (r -= p.weight) < 0) ?? people.at(-1);
      const own = macs.filter((m) => m.owner === who);
      const m = own.length > 1 && rand() < 0.3 ? own[1] : own[0];
      const allowed = teams[m.team] * MINUTE;
      const start = at(back, 9 * 60 + Math.floor(rand() * (latest - 9 * 60)));
      const held = rand() < 0.15 ? allowed : Math.max(2 * MINUTE, Math.round(allowed * (0.1 + rand() * 0.8)));
      if (start + held > now - 30 * MINUTE || !free(m, start, start + held)) continue;
      if (back >= PERIOD_DAYS && start >= since) continue; // keep the period's count exact
      session(m, who, start, start + held, pick(reasons[m.team]));
      return;
    }
  }

  // Now: nine people with Privileges rights, one past its expiry, and an account without one.
  for (const [name, minutes, reason] of elevatedNow) {
    const m = macs.find((x) => x.owner === person(name));
    const id = session(m, person(name), ago(minutes), null, reason);
    open.set(m.serial, [{ user: person(name).user, id, source: "privileges", start: ago(minutes) }]);
  }
  // Emma quit Privileges' agent, which runs the timer that would have taken her rights
  // back, so she kept them past their expiry and the agent reports both.
  const emma = macs.find((m) => m.owner === person("Emma Novak"));
  const emmaSession = open.get(emma.serial)[0];
  add(emma, ev(emma, "agent.tamper", ago(33), { detail: { check: "privileges_timer", state: "failed",
    problem: "Privileges' timer isn't running for enovak, who holds admin rights it granted" } }));
  add(emma, ev(emma, "elevation.overdue", ago(16), { user: emmaSession.user, session: emmaSession.id,
    elevation: { reason: null, expires: iso(ago(21)), source: "privileges" },
    detail: { trigger: "heartbeat", expired_at: iso(ago(21)), grace_seconds: 300, observed_admin: true,
      enforcement: "alert", enforcement_failed: false } }));
  // The contractor's loaner Mac: its local account is in the admin group with no grant.
  const oob = randomUUID(), outOfBand = { reason: null, expires: null, source: "out_of_band" };
  add(contractor, ev(contractor, "admin.out_of_band", ago(26), { user: ["contractor"], session: oob, elevation: outOfBand,
    detail: { first_observed: iso(ago(26)) } }));
  open.set(contractor.serial, [{ user: ["contractor"], id: oob, source: "out_of_band", start: ago(26) }]);
  busy.get(contractor.serial).push([ago(26), now]);
  inPeriod++;

  // Earlier today, then the days before: few at weekends, and the period's total exact.
  const minuteNow = today.hour * 60 + today.minute;
  const workday = (back) => weekday(back) !== 0 && weekday(back) !== 6;
  const weights = Array.from({ length: HISTORY_DAYS },
    (_, back) => (workday(back) ? 0.6 + rand() * 0.8 : rand() < 0.5 ? 0 : 0.05 + rand() * 0.1));
  const todayShare = workday(0) ? Math.max(0, Math.min(1, (minuteNow - 60 - 9 * 60) / (8.5 * 60))) : 0;
  const perWeight = (IN_PERIOD - inPeriod) / (weights.slice(1, PERIOD_DAYS).reduce((a, b) => a + b, 0) + weights[0] * todayShare);
  // Fewer than a whole day's, as the people elevated now are today's too.
  const todayCount = Math.round(weights[0] * todayShare * perWeight * 0.4);
  for (let i = 0; i < todayCount; i++) past(0, Math.min(17 * 60 + 30, minuteNow - 60));
  // Largest remainders, so the days add up to exactly what the period still needs.
  const need = IN_PERIOD - inPeriod, scale = need / weights.slice(1, PERIOD_DAYS).reduce((a, b) => a + b, 0);
  const days = weights.slice(1, PERIOD_DAYS).map((w, i) => ({ back: i + 1, exact: w * scale }));
  for (const d of days) d.n = Math.floor(d.exact);
  const short = need - days.reduce((sum, d) => sum + d.n, 0);
  for (const d of [...days].sort((a, b) => (b.exact % 1) - (a.exact % 1)).slice(0, short)) d.n++;
  for (const d of days) for (let i = 0; i < d.n; i++) past(d.back);
  for (let back = PERIOD_DAYS; back < HISTORY_DAYS; back++) {
    for (let i = Math.floor(weights[back] * perWeight + rand()); i > 0; i--) past(back);
  }
  if (inPeriod !== IN_PERIOD) throw new Error(`seeded ${inPeriod} elevations in the period, not ${IN_PERIOD}`);

  // Five weeks ago someone made an admin account by hand on Ben's Mac. Privileges' system
  // extension logged who did it, the agent saw the new account, and it was revoked from the
  // console. It falls outside the Overview's 30 days.
  const ben = macs.find((m) => m.serial === "C02YH2CCJG5H");
  let back = 37;
  while (!workday(back)) back++;
  const found = at(back, 14 * 60 + 44), backdoor = ["svc-backup"], incident = randomUUID();
  add(ben, ev(ben, "admin.out_of_band", found, { user: backdoor, session: incident, elevation: outOfBand,
    detail: { first_observed: iso(found), instigator: { executable: "/usr/sbin/dseditgroup", signing_id: "com.apple.dseditgroup",
      team_id: "", platform_binary: true, pid: 4127, ppid: 4120, tty: "/dev/ttys002", logged_at: iso(found - 30_000) } } }));
  add(ben, ev(ben, "persistence.detected", found + 6_000, { user: backdoor, session: incident, elevation: outOfBand,
    detail: { since: iso(found - 5 * MINUTE), truncated: 0, findings: [
      { kind: "local_account", change: "added", name: "svc-backup", uid: 503, admin: true }] } }));
  add(ben, ev(ben, "elevation.revoked", found + 5 * MINUTE, { user: backdoor, session: incident, elevation: outOfBand,
    detail: { trigger: "command", command_id: randomUUID(), observed_admin: false, verified: true } }));

  // Today an IT admin signed in to the build Mac over SSH, and Privileges' system extension
  // blocked an attempt to move Privileges aside.
  const mv = { executable: "/bin/mv", signing_id: "com.apple.mv", team_id: "", platform_binary: true,
    pid: 4133, ppid: 4120, tty: "/dev/ttys002" };
  add(build, ev(build, "admin.permanent_use", ago(31), { user: ["itadmin"], detail: { use_id: randomUUID(), method: "ssh",
    state: "ended", source: "utmpx", started: iso(ago(44)), ended: iso(ago(31)), end_basis: "logged", tty: "ttys002",
    remote_host: "10.20.4.15" } }));
  add(build, ev(build, "agent.tamper", ago(36), { detail: { check: "privileges_blocked", state: "detected",
    problem: "SAP Privileges blocked /bin/mv from trying to rename /Applications/Privileges.app",
    blocked_action: "RENAME", item: "/Applications/Privileges.app", attempts: 1, instigator: mv,
    first_attempt: iso(ago(36.5)), last_attempt: iso(ago(36.5)) } }));

  // Each Mac's first check-in, and its latest, a few minutes apart across the fleet as
  // the agents' 5-minute heartbeats fall.
  const checkIns = new Map();
  for (const m of macs) {
    const elevated = open.get(m.serial) ?? [];
    const newest = Math.min(...elevated.map((s) => (now - s.start) / MINUTE), 5);
    checkIns.set(m.serial, now - Math.floor(rand() * Math.max(0.5, newest - 0.5) * MINUTE));
    add(m, health(m, at(HISTORY_DAYS - 1, 8 * 60 + Math.floor(rand() * 60)), []));
    add(m, health(m, checkIns.get(m.serial), elevated));
  }
  function health(m, ms, elevated) {
    const integrity = { code_signature: true, launch_daemon: true, settings_managed: true, privileges_tamper_protection: true,
      privileges_hook: true, privileges_timer: !(m === emma && elevated.length), privileges_expiry_cap: true, privileges_give_back_hook: true,
      privileges_revoke_exclusions: true };
    return ev(m, "agent.health", ms, { detail: {
      admin_members: [...elevated.map((s) => s.user[0]), "itadmin"].sort(), permanent_admins: ["itadmin"],
      open_sessions: elevated.map((s) => ({ user: s.user[0], session_id: s.id, source: s.source })), queue_depth: 0,
      privileges: { installed: true, post_change_hook_configured: true, pass_reason_to_executable: true,
        enforce_privileges: null, system_extension_enabled: true, admin_budget_minutes: null,
        expiration_interval_minutes: teams[m.team], expiration_interval_max_minutes: null, expiry_capped: true,
        allow_privilege_renewal: false, auto_renewal_configured: false, post_change_action_on_grant_only: false,
        revoke_at_login: true, revoke_at_login_excluded_users: ["itadmin"], revoke_after_time_change: null,
        revoke_after_time_change_excluded_users: null },
      integrity, persistence_unreadable: [],
    } });
  }

  await waitForAPI(server);
  // Re-running enrols the same serials again; without this they would all wait for approval.
  await request("PUT", "/v1/settings", { bearer: CONSOLE, body: { reenrollment_requires_approval: false } });
  await Promise.all(macs.map(async (m) => {
    Object.assign(m, await enroll(m.serial));
    const list = events.get(m.serial).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    for (let i = 0; i < list.length; i += 500) {
      const r = await request("POST", "/v1/agent/events", { mac: m, body: { events: list.slice(i, i + 500) } });
      if (r.rejected.length) throw new Error(`${m.serial}: ${r.rejected[0].error}`);
    }
  }));
  // Check-ins are timed by the server's clock, so the API records each Mac's as now; move
  // them back to when the agents sent them, in `make db`'s Postgres.
  try {
    psql(database, `UPDATE devices d SET last_seen_at = v.at::timestamptz,
      state = jsonb_set(d.state, '{last_received_at}', to_jsonb(v.at)) FROM (VALUES ${
      [...checkIns].map(([s, ms]) => `('${s}', '${iso(ms)}')`).join(", ")}) v(serial, at) WHERE d.serial = v.serial`);
  } catch (err) {
    console.warn(`Couldn't backdate the check-ins in make db's Postgres, so every Mac checked in just now: ${err.stderr?.toString().trim() || err.message}`);
  }

  // Grace's Mac was reinstalled and waits for approval to enrol again.
  await request("PUT", "/v1/settings", { bearer: CONSOLE, body: { reenrollment_requires_approval: true } });
  const again = await enroll(macs.find((m) => m.owner === person("Grace Adeyemi")).serial);
  const sessions = [...events.values()].flat().filter((e) => e.type === "elevation.granted" || e.type === "admin.out_of_band").length;
  console.log(`Seeded ${macs.length} Macs and ${sessions} sessions over ${HISTORY_DAYS} days, ${IN_PERIOD} in the last ` +
    `${PERIOD_DAYS}; ${[...open.values()].flat().length} people have admin rights now; one Mac re-enrolled (${again.status}).`);

  /** Answers the console's revokes for a Mac as its agent would: the rights go, the session
   *  ends and the command is reported done. Returns how many it answered. */
  async function applyRevokes(serialNumber) {
    const m = macs.find((x) => x.serial === serialNumber);
    const { commands } = await request("GET", "/v1/agent/commands", { mac: m });
    for (const c of commands) {
      const done = Date.now(), held = open.get(m.serial) ?? [];
      const ending = held.filter((s) => c.session_id ? s.id === c.session_id : !c.user || s.user[0] === c.user);
      const kept = held.filter((s) => !ending.includes(s));
      await request("POST", "/v1/agent/events", { mac: m, body: { events: [
        ...ending.map((s) => ev(m, "elevation.revoked", done, { user: s.user, session: s.id,
          elevation: { reason: null, expires: null, source: s.source },
          detail: { trigger: "command", command_id: c.command_id, observed_admin: false, verified: true } })),
        health(m, done, kept)] } });
      open.set(m.serial, kept);
      await request("POST", `/v1/agent/commands/${c.command_id}/result`, { mac: m, body: { status: "completed",
        error: null, revoked: ending.map((s) => s.user[0]), failed: [], skipped: [], completed_at: new Date(done).toISOString() } });
    }
    return commands.length;
  }
  return { contractor: contractor.serial, blocked: build.serial, applyRevokes };
}

/** Waits up to 30 seconds for the API, which may still be starting, then explains. */
async function waitForAPI(server) {
  for (let attempt = 1; ; attempt++) {
    try {
      if ((await fetch(server + "/healthz")).ok) return;
    } catch {}
    if (attempt === 15) throw new Error(`Can't reach the API at ${server}. Start it with \`make run-api\` in another terminal, leave it running, and run this again.`);
    if (attempt === 1) console.log(`Waiting for the API at ${server}...`);
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

/** Runs SQL in `make db`'s Postgres. */
function psql(database, sql) {
  execFileSync("docker", ["compose", "-f", new URL("compose.yaml", import.meta.url).pathname,
    "exec", "-T", "postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "altiward", "-d", database, "-c", sql],
  { stdio: ["ignore", "ignore", "pipe"] });
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await seedSite(process.argv[2] ?? "http://127.0.0.1:8080").catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
