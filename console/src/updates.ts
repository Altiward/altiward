// The update check: the admin's browser asks GitHub's public releases API whether a newer
// server or agent is out. The server never asks anyone. It runs only while GET /v1/about
// reports update_check (ALTIWARD_UPDATE_CHECK), which is also when the console's CSP lets
// it reach api.github.com.

/** Server and agent releases share one repository, told apart by tag prefix. */
export const RELEASES_URL = "https://api.github.com/repos/Altiward/altiward/releases?per_page=50";

/** The fields of a GitHub release the check reads. */
export interface GitHubRelease {
  tag_name: string;
  html_url: string;
  body: string | null;
  draft: boolean;
  prerelease: boolean;
  published_at: string | null;
  assets: { name: string; browser_download_url: string }[];
}

export type Product = "server" | "agent";

/** The newest release of a product. */
export interface Latest {
  version: string;
  /** The release page. */
  url: string;
  /** The notes' Security section lists a fix. */
  security: boolean;
  /** The agent's package; null for the server. */
  packageUrl: string | null;
  /** A release candidate: GitHub marks it a pre-release, or its version is one. */
  prerelease: boolean;
}

const tagPrefix: Record<Product, string> = { server: "server-v", agent: "agent-v" };

/** X.Y.Z, optionally with a pre-release such as -rc.1. Build metadata (+…) is allowed. */
export function isVersion(v: string): boolean {
  return /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.test(v);
}

export function isPrerelease(v: string): boolean {
  return isVersion(v) && v.split("+")[0].includes("-");
}

/** Semantic version order, as upgrade.sh's compare: 0.3.0-rc.1 < 0.3.0-rc.2 <
 *  0.3.0. Build metadata is ignored, and a version that isn't X.Y.Z, such as dev, counts
 *  as 0.0.0. */
export function compareVersions(a: string, b: string): -1 | 0 | 1 {
  const split = (v: string) => {
    v = v.split("+")[0];
    const dash = v.indexOf("-");
    let core = dash < 0 ? v : v.slice(0, dash);
    let pre = dash < 0 ? "" : v.slice(dash + 1);
    if (!/^\d+(\.\d+){0,2}$/.test(core)) { core = "0"; pre = ""; }
    const nums = core.split(".").map(Number);
    return { nums: [0, 1, 2].map((i) => nums[i] ?? 0), pre };
  };
  const x = split(a), y = split(b);
  for (let i = 0; i < 3; i++) {
    if (x.nums[i] !== y.nums[i]) return x.nums[i] < y.nums[i] ? -1 : 1;
  }
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1; // a release sorts after its pre-releases
  if (!y.pre) return -1;
  const p = x.pre.split("."), q = y.pre.split(".");
  for (let i = 0; ; i++) {
    if (i >= p.length && i >= q.length) return 0;
    if (i >= p.length) return -1; // fewer parts sort first
    if (i >= q.length) return 1;
    const pn = /^\d+$/.test(p[i]), qn = /^\d+$/.test(q[i]);
    if (pn && qn) {
      const d = Number(p[i]) - Number(q[i]);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (pn) return -1; // numbers sort before words
    else if (qn) return 1;
    else if (p[i] !== q[i]) return p[i] < q[i] ? -1 : 1;
  }
}

/** Whether release notes' "### Security" section lists something, not "None.". */
export function hasSecurityFix(notes: string | null): boolean {
  if (!notes) return false;
  const lines = notes.split(/\r?\n/);
  const start = lines.findIndex((l) => /^#{1,6}\s+Security\s*$/i.test(l.trim()));
  if (start < 0) return false;
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => /^#{1,6}\s/.test(l.trim()));
  const text = (end < 0 ? rest : rest.slice(0, end)).join("\n").trim();
  return text !== "" && !/^none\.?$/i.test(text);
}

/** The newest release of product in the list, skipping drafts, and pre-releases unless asked. */
export function latestRelease(releases: GitHubRelease[], product: Product, { prereleases }: { prereleases: boolean }): Latest | null {
  let best: { release: GitHubRelease; version: string } | null = null;
  for (const r of releases) {
    if (r.draft || !r.tag_name.startsWith(tagPrefix[product])) continue;
    const version = r.tag_name.slice(tagPrefix[product].length);
    if (!isVersion(version)) continue;
    if (!prereleases && (r.prerelease || isPrerelease(version))) continue;
    if (!best || compareVersions(version, best.version) > 0) best = { release: r, version };
  }
  if (!best) return null;
  const pkg = product === "agent" ? best.release.assets?.find((a) => a.name.endsWith(".pkg")) : undefined;
  return {
    version: best.version, url: best.release.html_url, security: hasSecurityFix(best.release.body),
    packageUrl: pkg?.browser_download_url ?? null, prerelease: best.release.prerelease || isPrerelease(best.version),
  };
}

export interface Available {
  /** The newest release of each product. */
  server: Latest | null;
  agent: Latest | null;
  /** The newest release candidate, when candidates count and it's newer than the release. */
  serverCandidate: Latest | null;
  agentCandidate: Latest | null;
  /** The newest of each, when newer than what runs: the server, and the newest agent in the fleet. */
  newerServer: Latest | null;
  newerAgent: Latest | null;
  /** The newest agent version in the fleet, if any Mac reported one. */
  fleetAgent: string | null;
}

/** What's newer than the running server and the newest agent in the fleet. Release
 *  candidates count when an admin shows pre-releases, and always for a server running
 *  one; a server that isn't X.Y.Z, such as dev, gets no notice. */
export function available(running: string, fleetAgents: string[], releases: GitHubRelease[],
  { prereleases = false }: { prereleases?: boolean } = {}): Available {
  const candidates = prereleases || isPrerelease(running);
  const newest = (product: Product) => {
    const release = latestRelease(releases, product, { prereleases: false });
    const any = candidates ? latestRelease(releases, product, { prereleases: true }) : null;
    const candidate = any && (!release || compareVersions(any.version, release.version) > 0) ? any : null;
    return { release, candidate, top: candidate ?? release };
  };
  const server = newest("server"), agent = newest("agent");
  const fleetAgent = fleetAgents.filter(isVersion).sort(compareVersions).at(-1) ?? null;
  return {
    server: server.release, agent: agent.release, serverCandidate: server.candidate, agentCandidate: agent.candidate, fleetAgent,
    newerServer: server.top && isVersion(running) && compareVersions(server.top.version, running) > 0 ? server.top : null,
    newerAgent: agent.top && fleetAgent && compareVersions(agent.top.version, fleetAgent) > 0 ? agent.top : null,
  };
}

/** The outcome of a check: the release list, or failed, with when it last worked. */
export interface Check {
  releases: GitHubRelease[] | null;
  /** When the release list was last fetched; null if never. */
  checkedAt: string | null;
  failed: boolean;
}

const CACHE_KEY = "altiward.releases";
const DISMISSED_KEY = "altiward.updates.dismissed";
const PRERELEASES_KEY = "altiward.updates.prereleases";
const DAY = 24 * 60 * 60 * 1000;
/** After a failure, wait this long before asking again. */
const RETRY_AFTER = 60 * 60 * 1000;
/** Check now asks at most this often. */
const PRESS_AFTER = 60 * 1000;

interface Cache { checkedAt?: string; releases?: GitHubRelease[]; failedAt?: string }

/** Stands in for localStorage while it's blocked or full, so the cache and dismissals
 *  still hold for this tab and the check keeps to its rate. Set only when a write to
 *  localStorage fails, and dropped when one succeeds. */
const memory = new Map<string, string>();

/** Empties the in-memory stand-in (tests). */
export function forgetMemory() {
  memory.clear();
}

function read<T>(key: string): T | null {
  let raw = memory.get(key) ?? null;
  if (raw === null) {
    try {
      raw = localStorage.getItem(key);
    } catch {
      raw = null;
    }
  }
  try {
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function write(key: string, value: unknown) {
  const raw = JSON.stringify(value);
  try {
    localStorage.setItem(key, raw);
    memory.delete(key);
  } catch {
    memory.set(key, raw);
  }
}

const trim = (r: GitHubRelease): GitHubRelease => ({
  tag_name: String(r.tag_name ?? ""), html_url: String(r.html_url ?? ""), body: typeof r.body === "string" ? r.body : null,
  draft: !!r.draft, prerelease: !!r.prerelease, published_at: r.published_at ?? null,
  assets: Array.isArray(r.assets) ? r.assets.map((a) => ({ name: String(a.name ?? ""), browser_download_url: String(a.browser_download_url ?? "") })) : [],
});

/** Whether the list predates the running server: it's newer than every server release
 *  listed. A server that isn't X.Y.Z, such as dev, never is. */
function predates(releases: GitHubRelease[], running: string): boolean {
  if (!isVersion(running)) return false;
  const newest = latestRelease(releases, "server", { prereleases: true });
  return !newest || compareVersions(running, newest.version) > 0;
}

/** Asks GitHub for the release list: at most once a day per browser after a successful
 *  check (the answer is kept in localStorage, or in memory for the tab when storage is
 *  blocked), and at most once an hour while GitHub can't be reached. A list that predates
 *  the running server, as after an upgrade, is asked for again at most once an hour, and
 *  kept if that fails. A failure is quiet. With force (Check now), it asks whatever it
 *  has, at most once a minute, and reports a failure. It sends no cookies, no referrer
 *  and no versions. */
export async function checkReleases(now = Date.now(), { running, force = false }: { running?: string; force?: boolean } = {}): Promise<Check> {
  const cache = read<Cache>(CACHE_KEY) ?? {};
  const lastSuccess = cache.checkedAt ?? null;
  const within = (at: string | null | undefined, ms: number) => !!at && now >= Date.parse(at) && now - Date.parse(at) < ms;
  const cached: Check | null = cache.releases && within(lastSuccess, DAY)
    ? { releases: cache.releases, checkedAt: lastSuccess, failed: false } : null;
  const failed: Check = { releases: null, checkedAt: lastSuccess, failed: true };
  const pressed = force && !within(lastSuccess, PRESS_AFTER) && !within(cache.failedAt, PRESS_AFTER);
  if (!pressed) {
    if (cached && !(running && predates(cache.releases!, running) && !within(lastSuccess, RETRY_AFTER))) return cached;
    if (within(cache.failedAt, RETRY_AFTER)) return cached ?? failed;
  }
  try {
    const res = await fetch(RELEASES_URL, {
      credentials: "omit", referrerPolicy: "no-referrer", headers: { Accept: "application/vnd.github+json" },
    });
    if (!res.ok) throw new Error(`GitHub returned ${res.status}`);
    const body: unknown = await res.json();
    if (!Array.isArray(body)) throw new Error("not a release list");
    const releases = (body as GitHubRelease[]).filter((r) => r && typeof r === "object").map(trim);
    const checkedAt = new Date(now).toISOString();
    write(CACHE_KEY, { checkedAt, releases } satisfies Cache);
    return { releases, checkedAt, failed: false };
  } catch {
    write(CACHE_KEY, { ...cache, failedAt: new Date(now).toISOString() } satisfies Cache);
    return pressed ? failed : cached ?? failed;
  }
}

/** Whether an admin dismissed the notice for this version. */
export function isDismissed(product: Product, version: string): boolean {
  return read<Partial<Record<Product, string>>>(DISMISSED_KEY)?.[product] === version;
}

/** Hides the notice for this version; the next version shows again. */
export function dismiss(product: Product, version: string) {
  write(DISMISSED_KEY, { ...read<Partial<Record<Product, string>>>(DISMISSED_KEY), [product]: version });
}

/** Whether this browser's admin asked to hear about release candidates (Settings' Show
 *  pre-releases). Off until turned on; nothing is sent to the server. */
export function showsPrereleases(): boolean {
  return read<boolean>(PRERELEASES_KEY) === true;
}

export function setShowPrereleases(on: boolean) {
  write(PRERELEASES_KEY, on);
}
