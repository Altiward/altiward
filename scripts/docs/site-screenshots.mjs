// Regenerates the console screenshots on altiward.com, in light and dark, from the example
// organisation in dev/seed-site.mjs: Overview, Fleet and Admins now as whole windows, with
// WebP copies 800, 1440 and 2880 pixels wide, and crops of the detail panel and the revoke
// dialog with a WebP copy each. It also makes the README's docs/images/console-overview.png.
// Rerun it when a release changes a pictured screen, then commit the pictures in both
// checkouts and check the site's alt text and captions still match them.
//
// Usage: make site-screenshots [SITE=../altiward.com]. Needs `make console-install`, once
// `npx --prefix console playwright install chromium`, and cwebp (`brew install webp`). It
// runs its own API on :8092 against a throwaway database in `make db`'s Postgres, so a
// running `make run-api` and its data are left alone.
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { seedSite } from "../../dev/seed-site.mjs";

const root = new URL("../../", import.meta.url).pathname;
const { chromium } = createRequire(join(root, "console/package.json"))("playwright");

const site = resolve(process.argv[2] ?? join(root, "../altiward.com"));
if (!existsSync(join(site, "images"))) {
  console.error(`${site} isn't an altiward.com checkout: give its path, as in make site-screenshots SITE=../altiward.com`);
  process.exit(1);
}
try {
  execFileSync("cwebp", ["-version"], { stdio: "ignore" });
} catch {
  console.error("cwebp isn't installed: it makes the site's WebP copies (brew install webp)");
  process.exit(1);
}

const PORT = 8092;
const SERVER = `http://127.0.0.1:${PORT}`;
const DATABASE = "altiward_site_screenshots";
const OUT = join(site, "images");
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
/** cwebp's quality, which keeps the copies near the size of the pictures they replaced. */
const WEBP_QUALITY = "80";

const psql = (database, sql) => execFileSync("docker", ["compose", "-f", join(root, "dev/compose.yaml"),
  "exec", "-T", "postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "altiward", "-d", database, "-c", sql],
{ stdio: ["ignore", "ignore", "inherit"] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The console shows the server's version. The site pictures the release being prepared, so
// this is the newest Server section, released or not.
const version = readFileSync(join(root, "CHANGELOG.md"), "utf8").match(/^## Server (\S+) - /m)[1];
const work = mkdtempSync(join(tmpdir(), "altiward-site-screenshots-"));
const api = join(work, "altiward-api");
execFileSync("go", ["build", "-ldflags", `-X main.version=${version}`, "-o", api, "./backend/cmd/altiward-api"],
  { cwd: root, stdio: "inherit" });

let server;
const browser = await chromium.launch();
try {
  psql("altiward", `DROP DATABASE IF EXISTS ${DATABASE} WITH (FORCE)`);
  psql("altiward", `CREATE DATABASE ${DATABASE}`);
  server = spawn(api, [], { env, stdio: ["ignore", "ignore", "inherit"] });
  const organisation = await seedSite(SERVER, { database: DATABASE });

  // Each picture in both appearances, one straight after the other, so times shown match.
  const pages = { light: await newPage("light"), dark: await newPage("dark") };
  const each = async (shoot) => { for (const [scheme, page] of Object.entries(pages)) await shoot(page, scheme); };
  const open = (page, path) => page.goto(SERVER + path);
  const select = async (page, table, text) => {
    await page.getByRole("grid", { name: table }).getByRole("row").filter({ hasText: text }).first().click();
    await page.mouse.move(800, 20); // off the row, so it shows selected, not hovered
  };
  /** Waits for text the picture must show, then for the page to settle. */
  const ready = async (page, showing) => {
    await page.getByText(showing).first().waitFor();
    await page.waitForLoadState("networkidle");
  };

  // Whole windows, at 1440 by 900 and twice the pixel density.
  await each(async (page, scheme) => {
    await open(page, "/overview");
    await ready(page, "Elevations per day");
    await whole(page, "overview", scheme);
  });
  // The README's picture: the Overview at the size GitHub shows it.
  const readme = await newPage("light", 1);
  await open(readme, "/overview");
  await ready(readme, "Elevations per day");
  await readme.screenshot({ path: join(root, "docs/images/console-overview.png"), animations: "disabled" });
  await each(async (page, scheme) => {
    await open(page, "/fleet");
    await ready(page, "Agent outdated");
    await whole(page, "fleet", scheme);
  });
  await each(async (page, scheme) => {
    await open(page, "/admins");
    await select(page, "People with admin rights", "priya.raman@");
    await ready(page, "Configuring a VPN client");
    await page.locator(".inspector .timeline li").first().waitFor();
    await whole(page, "admins-now", scheme);
  });

  // Crops, in a taller window so that no detail panel scrolls.
  for (const page of Object.values(pages)) await page.setViewportSize({ width: 1440, height: 1400 });
  await each(async (page, scheme) => {
    await open(page, `/fleet?q=${organisation.blocked}`);
    await select(page, "Macs", organisation.blocked);
    await ready(page, "Privileges blocked tampering");
    await crop(page, "blocked", scheme, '[role="group"][aria-labelledby="integrity-title"]');
  });
  await each(async (page, scheme) => {
    await open(page, "/sessions?q=svc-backup");
    await select(page, "Sessions", "svc-backup");
    await ready(page, "From the console");
    await crop(page, "added-by", scheme);
  });
  // Revoking the account without a grant: find it, confirm, and the session on record.
  await each(async (page, scheme) => {
    await open(page, "/admins");
    await select(page, "People with admin rights", "contractor");
    await page.locator(".inspector .timeline li").first().waitFor();
    await ready(page, "Found without a grant");
    await crop(page, "revoke-find", scheme);
    await page.getByRole("button", { name: "Revoke admin rights…" }).click();
    await page.mouse.move(800, 20);
    await crop(page, "revoke-confirm", scheme, "dialog.sheet");
    await page.getByRole("button", { name: scheme === "dark" ? "Revoke" : "Cancel", exact: true }).click();
  });
  for (let i = 0; !(await organisation.applyRevokes(organisation.contractor)); i++) {
    if (i === 20) throw new Error(`the console's revoke didn't reach ${organisation.contractor}`);
    await sleep(500);
  }
  await each(async (page, scheme) => {
    await open(page, "/sessions?q=contractor");
    await select(page, "Sessions", "contractor");
    await ready(page, "From the console");
    await crop(page, "revoke-record", scheme);
  });
  console.log(`Screenshots written to ${OUT}, and the README's to docs/images/console-overview.png`);
} finally {
  await browser.close();
  if (server) {
    const exited = new Promise((r) => server.once("exit", r));
    server.kill();
    await exited;
  }
  rmSync(work, { recursive: true, force: true });
}

/** The whole window as console-<name>-<scheme>.png, and its WebP copies at three widths. */
async function whole(page, name, scheme) {
  const png = join(OUT, `console-${name}-${scheme}.png`);
  await page.screenshot({ path: png, animations: "disabled" });
  for (const width of [800, 1440, 2880]) {
    webp(png, join(OUT, `console-${name}-${scheme}-${width}.webp`), width === 2880 ? [] : ["-resize", String(width), "0"]);
  }
}

/** The detail panel, full width, from its top to below its last group or around one group
 *  (`group`), or another element such as a dialog: as console-<name>-<scheme>.png and .webp. */
async function crop(page, name, scheme, target) {
  await page.waitForLoadState("networkidle");
  const png = join(OUT, `console-${name}-${scheme}.png`);
  if (target && !target.startsWith("[role")) {
    await page.locator(target).first().screenshot({ path: png, animations: "disabled" });
  } else {
    const clip = await page.locator(".inspector").first().evaluate((el, group) => {
      const box = el.getBoundingClientRect();
      const pad = parseFloat(getComputedStyle(el).paddingBottom);
      if (group) {
        const g = el.querySelector(group).getBoundingClientRect();
        return { x: box.x, y: g.y - pad, width: box.width, height: g.height + 2 * pad };
      }
      const bottom = Math.max(...[...el.children].map((c) => c.getBoundingClientRect().bottom));
      return { x: box.x, y: box.y, width: box.width, height: Math.min(box.height, bottom - box.y + pad) };
    }, target ?? null);
    await page.screenshot({ path: png, clip, animations: "disabled" });
  }
  webp(png, join(OUT, `console-${name}-${scheme}.webp`), []);
}

function webp(png, out, args) {
  execFileSync("cwebp", ["-quiet", "-q", WEBP_QUALITY, "-m", "6", ...args, png, "-o", out], { stdio: "inherit" });
}

/** A page at 1440x900 and twice the pixel density (or `scale`), in the given appearance,
 *  signed in with the dev token as the sign-in page would store it. */
async function newPage(scheme, scale = 2) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 }, deviceScaleFactor: scale, colorScheme: scheme,
    reducedMotion: "reduce", locale: "en-GB", timezoneId: "Europe/London",
  });
  await context.addInitScript((token) => sessionStorage.setItem("altiward.consoleToken", token), TOKEN);
  return context.newPage();
}
