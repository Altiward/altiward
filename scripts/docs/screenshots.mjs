// Regenerates the console screenshots in the install guide (docs/images/install/), in light
// and dark, from `make console-seed`'s demo data. Rerun it after a console change that
// alters a pictured screen. The README's docs/images/console-overview.png isn't one of
// them: it needs months of history, which the seed doesn't make.
//
// Usage: make docs-screenshots. Needs `make console-install` and, once,
// `npx --prefix console playwright install chromium`. It runs its own API on :8091 against
// a throwaway database in `make db`'s Postgres, so a running `make run-api` and its data
// are left alone.
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("../../", import.meta.url).pathname;
const { chromium } = createRequire(join(root, "console/package.json"))("playwright");

const PORT = 8091;
const SERVER = `http://127.0.0.1:${PORT}`;
const DATABASE = "altiward_screenshots";
const OUT = join(root, "docs/images/install");
const TOKEN = "dev-console-token-001";
const env = {
  ...process.env,
  ALTIWARD_LISTEN_ADDR: `127.0.0.1:${PORT}`,
  ALTIWARD_DATABASE_URL: `postgres://altiward:altiward@127.0.0.1:5433/${DATABASE}?sslmode=disable`,
  ALTIWARD_AGENT_TOKENS: "dev=dev-agent-token-0001",
  ALTIWARD_CONSOLE_TOKENS: `dev=${TOKEN}`,
  ALTIWARD_CONSOLE_DIR: join(root, "console/dist"),
  ALTIWARD_UPDATE_CHECK: "false", // no call to GitHub, and no update notice in the pictures
};

const psql = (database, sql) => execFileSync("docker", ["compose", "-f", join(root, "dev/compose.yaml"),
  "exec", "-T", "postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "altiward", "-d", database, "-c", sql],
{ stdio: ["ignore", "ignore", "inherit"] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A syslog receiver that accepts and discards, so Settings shows the SIEM as up to date.
const syslog = net.createServer((socket) => socket.resume()).listen(0, "127.0.0.1");
await new Promise((r) => syslog.once("listening", r));

// The console shows the server's version: use the latest release's, not "dev".
const version = readFileSync(join(root, "CHANGELOG.md"), "utf8").match(/^## Server (\S+) - \d{4}-/m)[1];
const work = mkdtempSync(join(tmpdir(), "altiward-screenshots-"));
const api = join(work, "altiward-api");
execFileSync("go", ["build", "-ldflags", `-X main.version=${version}`, "-o", api, "./backend/cmd/altiward-api"],
  { cwd: root, stdio: "inherit" });

let server;
async function startServer(extra = {}) {
  server = spawn(api, [], { env: { ...env, ...extra }, stdio: ["ignore", "ignore", "inherit"] });
  for (let i = 0; i < 100; i++) {
    if (await fetch(`${SERVER}/healthz`).then((r) => r.ok, () => false)) return;
    await sleep(200);
  }
  throw new Error("the API didn't start");
}
async function stopServer() {
  if (!server) return;
  const exited = new Promise((r) => server.once("exit", r));
  server.kill();
  await exited;
  server = undefined;
}

const browser = await chromium.launch();
try {
  psql("altiward", `DROP DATABASE IF EXISTS ${DATABASE} WITH (FORCE)`);
  psql("altiward", `CREATE DATABASE ${DATABASE}`);
  await startServer({
    ALTIWARD_SYSLOG_ADDR: `127.0.0.1:${syslog.address().port}`, ALTIWARD_SYSLOG_TLS: "false",
  });
  execFileSync("node", [join(root, "dev/seed.mjs"), SERVER], { env: { ...process.env, SEED_DATABASE: DATABASE }, stdio: "inherit" });
  // People signed in through single sign-on, for Settings. Only the token's hash is stored,
  // and these tokens are never used.
  psql(DATABASE, `INSERT INTO console_sessions
    (token_hash, tenant_id, subject, actor, name, role, csrf_token, created_at, ends_at, expires_at)
    SELECT sha256(convert_to(p.actor, 'UTF8')), d.tenant_id, p.actor, p.actor, p.name, p.role, 'unused',
      now() - p.since, now() - p.since + interval '12 hours', now() - p.since + interval '12 hours'
    FROM (SELECT DISTINCT tenant_id FROM devices) d,
      (VALUES ('priya.shah@example.com', 'Priya Shah', 'admin', interval '25 minutes'),
              ('tom.berg@example.com', 'Tom Berg', 'operator', interval '3 hours')) p(actor, name, role, since)`);

  mkdirSync(OUT, { recursive: true });
  for (const scheme of ["light", "dark"]) {
    const page = await newPage(scheme, { signedIn: true });
    // The whole window, or one element; an inspector is cut off below its last group. Each
    // waits for text it must show, since panels load their details separately.
    const shot = async (name, showing, target) => {
      await page.getByText(showing).first().waitFor();
      await page.waitForLoadState("networkidle");
      const path = join(OUT, `${name}-${scheme}.png`);
      if (!target) return page.screenshot({ path, animations: "disabled" });
      const element = page.locator(target).first();
      if (target !== ".inspector") return element.screenshot({ path, animations: "disabled" });
      const clip = await element.evaluate((el) => {
        const box = el.getBoundingClientRect();
        const bottom = Math.max(...[...el.children].map((c) => c.getBoundingClientRect().bottom));
        const style = getComputedStyle(el);
        return { x: box.x, y: box.y, width: box.width,
          height: Math.min(box.height, bottom - box.y + parseFloat(style.paddingBottom)) };
      });
      await page.screenshot({ path, clip, animations: "disabled" });
    };
    const open = async (path) => page.goto(SERVER + path);
    const select = async (table, text) => page.getByRole("grid", { name: table }).getByRole("row").filter({ hasText: text }).first().click();

    await open("/fleet");
    await shot("fleet", "C02TN5FFHV2P");
    await open("/sessions");
    await select("Sessions", "jane.doe@");
    await shot("session-granted", "Installing Xcode command line tools");
    await open("/sessions");
    await select("Sessions", "ben.wong@");
    await shot("session-revoked", "Homebrew upgrade", ".inspector");
    await exportsSent();
    await open("/settings");
    await shot("settings-siem", "Up to date", '[role="group"][aria-labelledby="siem-title"]');
    await shot("settings-signed-in", "Tom Berg", '[role="group"][aria-labelledby="signins-title"]');
    await open("/enrollments");
    await select("Enrollments", "C02XK0AAJGH5");
    await shot("enrollments", "This Mac enrolled again");
    await open("/fleet?show=attention");
    await select("Macs", "C02VJ4EEMD6R");
    await shot("fleet-hook-not-reporting", "PostChangeExecutableChecksum", '[role="group"][aria-labelledby="integrity-title"]');
    await open("/sessions");
    await select("Sessions", "contractor");
    await shot("session-without-grant", "Found without a grant", ".inspector");

    const signIn = await newPage(scheme, { signedIn: false });
    await signIn.goto(SERVER);
    await signIn.waitForLoadState("networkidle");
    await signIn.locator(".signin form").screenshot({ path: join(OUT, `sign-in-token-${scheme}.png`) });
    await page.context().close();
    await signIn.context().close();
  }

  // Single sign-on turns on with an issuer the server only contacts when someone signs in.
  await stopServer();
  await startServer({
    ALTIWARD_OIDC_ISSUER: "http://localhost:9/sso", ALTIWARD_OIDC_CLIENT_ID: "altiward",
    ALTIWARD_CONSOLE_URL: SERVER, ALTIWARD_OIDC_ADMIN_GROUPS: "altiward-admins",
  });
  for (const scheme of ["light", "dark"]) {
    const page = await newPage(scheme, { signedIn: false });
    await page.goto(SERVER);
    await page.waitForLoadState("networkidle");
    await page.locator(".signin form").screenshot({ path: join(OUT, `sign-in-sso-${scheme}.png`) });
    await page.context().close();
  }
  console.log(`Screenshots written to ${OUT}`);
} finally {
  await browser.close();
  await stopServer();
  syslog.close();
  rmSync(work, { recursive: true, force: true });
}

/** Waits until the SIEM export has nothing waiting, so Settings shows it as up to date. */
async function exportsSent() {
  for (let i = 0; i < 60; i++) {
    const r = await fetch(`${SERVER}/v1/exports`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then((r) => r.json());
    if (r.sinks.every((s) => s.pending === 0 && s.last_delivered_at)) return;
    await sleep(1000);
  }
  throw new Error("the SIEM export still has events waiting");
}

/** A page at 1280x800 and twice the pixel density, in the given appearance. The console
 *  follows the system's appearance by default; signedIn stores the dev token as the
 *  sign-in page would. */
async function newPage(scheme, { signedIn }) {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2, colorScheme: scheme,
    reducedMotion: "reduce", locale: "en-GB", timezoneId: "Europe/London",
  });
  if (signedIn) {
    await context.addInitScript((token) => sessionStorage.setItem("altiward.consoleToken", token), TOKEN);
  }
  return context.newPage();
}
