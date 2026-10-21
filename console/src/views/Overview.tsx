import { type ReactNode, useState } from "react";
import { Link } from "react-router";
import type { Overview, OverviewDays } from "../api";
import { Banner, Explain, Segmented, Toolbar } from "../components/Chrome";
import { EndedGlyph, NotGrantedGlyph, VerifiedGlyph } from "../components/Icons";
import { UpdateNotices } from "../components/Updates";
import { useApi } from "../context";
import { explanations as tips } from "../explanations";
import { formatDuration, relativeTime, sinkName } from "../format";
import { useLoad } from "../useLoad";

type Period = Overview["period"];
type Bucket = Period["buckets"][number];
type SourceKey = "privileges" | "without_grant";

/** Where admin rights come from, in stacking order, each with its own colour. */
const sources: { key: SourceKey; label: string; colour: string; tip: string }[] = [
  { key: "privileges", label: "Privileges", colour: "var(--muted)", tip: tips.privileges },
  { key: "without_grant", label: "Without a grant", colour: "var(--denied)", tip: tips.withoutGrant },
];

const periods: { value: `${OverviewDays}`; title: string }[] = [
  { value: "7", title: "7 days" }, { value: "30", title: "30 days" }, { value: "90", title: "90 days" },
];

const plural = (n: number, one: string, many: string) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const total = (b: Bucket) => b.privileges + b.without_grant;
const shortDate = (iso: string) => new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });

/** The first page: how things stand now, over the period, and the fleet's health. */
export function OverviewView() {
  const api = useApi();
  const [days, setDays] = useState<OverviewDays>(30);
  const { data, error, reload } = useLoad(() => api.overview(days), [days], 60_000);

  return (
    <>
      <Toolbar title="Overview" subtitle={data ? summary(data) : undefined} onRefresh={reload}>
        <Segmented label="Period" value={`${days}`} options={periods} onChange={(v) => setDays(Number(v) as OverviewDays)} />
      </Toolbar>
      <div className="split">
        <div className="pane">
          {error && <Banner>{error}</Banner>}
          <UpdateNotices fleetAgents={data?.health.agent_versions.map((v) => v.version) ?? []} />
          {data && (
            <div className="overview">
              <NowSection o={data} />
              <PeriodSection o={data} />
              <HealthSection o={data} />
            </div>
          )}
        </div>
      </div>
    </>
  );
}

function summary(o: Overview): string {
  const admins = o.now.admins;
  const alerts = o.now.past_expiry + o.now.macs_failing_checks + o.now.macs_silent;
  const who = admins === 0 ? "No one has admin rights now"
    : `${plural(admins, "person has", "people have")} admin rights now` +
      (o.now.without_grant ? `, ${o.now.without_grant.toLocaleString()} without a grant` : "");
  return `${who}. ${alerts === 0 ? "Nothing needs a look." : `${plural(alerts, "thing needs", "things need")} a look.`}`;
}

function Tile({ title, wide, children }: { title: ReactNode; wide?: boolean; children: ReactNode }) {
  return (
    <div className={`tile${wide ? " wide" : ""}`}>
      <h3>{title}</h3>
      {children}
    </div>
  );
}

const Swatch = ({ colour }: { colour: string }) => <span className="swatch" style={{ background: colour }} aria-hidden="true" />;

function NowSection({ o }: { o: Overview }) {
  const admins = o.now.admins;
  const rows = sources.map((s) => ({ ...s, n: o.now[s.key] }));
  return (
    <section aria-labelledby="overview-now">
      <h2 id="overview-now">Now</h2>
      <div className="tiles">
        <Tile title={<Explain tip={tips.adminsNow}>Admins now</Explain>}>
          <div className="figure">{admins.toLocaleString()}</div>
          {admins > 0 && (
            <div className="split-bar" aria-hidden="true">
              {rows.map((s) => s.n > 0 && <div key={s.key} style={{ flexGrow: s.n, background: s.colour }} />)}
            </div>
          )}
          <ul className="rows">
            {rows.map((s) => (
              <li key={s.key}>
                <span><Swatch colour={s.colour} /><Explain tip={s.tip}>{s.label}</Explain></span>
                <span className={`count${s.key === "without_grant" && s.n > 0 ? " denied" : ""}`}>{s.n.toLocaleString()}</span>
              </li>
            ))}
          </ul>
          <Link className="tile-link" to="/admins">Open Admins now</Link>
        </Tile>
        <Tile title={<Explain tip={tips.needsALook}>Needs a look</Explain>}>
          <ul className="rows">
            <Alert label="Rights past their expiry" tip={tips.pastExpiry} n={o.now.past_expiry} to="/admins" what={["person", "people"]} />
            <Alert label="Macs failing an integrity check" tip={tips.failingChecks} n={o.now.macs_failing_checks}
              to="/fleet?show=attention" what={["Mac", "Macs"]} />
            <Alert label="Macs not checking in" tip={tips.notCheckingIn} n={o.now.macs_silent} to="/fleet?show=silent" what={["Mac", "Macs"]} />
          </ul>
        </Tile>
      </div>
    </section>
  );
}

function Alert({ label, tip, n, to, what }: { label: string; tip: string; n: number; to: string; what: [string, string] }) {
  return (
    <li>
      <Explain tip={tip}>{label}</Explain>
      {n === 0
        ? <span className="secondary"><VerifiedGlyph /> None</span>
        : <Link to={to} className="tag denied" aria-label={`${label}: show ${plural(n, ...what)}`}><NotGrantedGlyph /> {n.toLocaleString()}</Link>}
    </li>
  );
}

function PeriodSection({ o }: { o: Overview }) {
  const p = o.period;
  return (
    <section aria-labelledby="overview-period">
      <h2 id="overview-period">Elevations <span className="when">Last {o.days} days</span></h2>
      <div className="tiles">
        <Tile wide title={<Explain tip={tips.elevations}>Elevations per {p.bucket_days === 1 ? "day" : "week"}</Explain>}>
          <div className="figures">
            <div><div className="figure">{p.elevations.toLocaleString()}</div><div className="secondary">elevations</div></div>
            <div>
              <div className={`figure${p.without_grant ? " denied" : ""}`}>{p.without_grant.toLocaleString()}</div>
              <div className="secondary"><Explain tip={tips.withoutGrant}>without a grant</Explain></div>
            </div>
          </div>
          <ElevationChart period={p} />
        </Tile>
        <Tile title="Time held against time allowed">
          <p className="note"><Explain tip={tips.median}>Median</Explain> per elevation that ended. The outlined bar is the time allowed, the solid bar the time held.</p>
          <Durations durations={p.durations} />
        </Tile>
        <Tile title="People who elevate most">
          {p.top_users.length === 0 ? <p className="note">No elevations in this period.</p> : (
            <table className="mini">
              <thead><tr><th>Person</th><th className="num">Elevations</th><th className="num">Macs</th></tr></thead>
              <tbody>
                {p.top_users.map((u) => (
                  <tr key={`${u.name}/${u.serial ?? ""}`}>
                    <td>
                      <Link to={`/sessions?q=${encodeURIComponent(u.name)}`}>{u.name}</Link>
                      {u.serial && <span className="secondary"> on <span className="data">{u.serial}</span></span>}
                    </td>
                    <td className="num">{u.elevations.toLocaleString()}</td>
                    <td className="num">{u.macs.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Tile>
        <Tile title="Macs with the most elevations">
          {p.top_macs.length === 0 ? <p className="note">No elevations in this period.</p> : (
            <table className="mini">
              <thead><tr><th>Mac</th><th className="num">Elevations</th><th className="num">People</th></tr></thead>
              <tbody>
                {p.top_macs.map((m) => (
                  <tr key={m.serial}>
                    <td><Link className="data" to={`/fleet?q=${encodeURIComponent(m.serial)}`}>{m.serial}</Link></td>
                    <td className="num">{m.elevations.toLocaleString()}</td>
                    <td className="num">{m.people.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Tile>
      </div>
    </section>
  );
}

/** Stacked columns, one per bucket, drawn with CSS so text stays crisp at any width. */
function ElevationChart({ period: p }: { period: Period }) {
  const [hover, setHover] = useState<number | null>(null);
  const n = p.buckets.length;
  const max = Math.max(1, ...p.buckets.map(total));
  // Label about five buckets, always including the newest.
  const step = n <= 7 ? 1 : Math.ceil(n / 5);
  const bucketName = (b: Bucket) => p.bucket_days === 1
    ? new Date(b.start).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })
    : `Week from ${shortDate(b.start)}`;
  const shown = hover === null ? null : p.buckets[hover];

  return (
    <div className="chart">
      <div className="legend" aria-hidden="true">
        {sources.map((s) => <span key={s.key}><Swatch colour={s.colour} />{s.label}</span>)}
      </div>
      <div className="chart-plot" aria-hidden="true" onMouseLeave={() => setHover(null)}>
        <span className="chart-max">{max.toLocaleString()}</span>
        <div className="chart-cols" style={{ gridTemplateColumns: `repeat(${n}, 1fr)` }}>
          {p.buckets.map((b, i) => (
            <div key={b.start} className={`chart-col${hover === i ? " hover" : ""}`} onMouseEnter={() => setHover(i)}>
              <div className="chart-stack" style={{ height: `${(total(b) / max) * 100}%` }}>
                {sources.map((s) => b[s.key] > 0 && <div key={s.key} style={{ flexGrow: b[s.key], background: s.colour }} />)}
              </div>
            </div>
          ))}
        </div>
        {shown && hover !== null && (
          <div className="chart-tip" style={{ left: `${Math.min(85, Math.max(15, ((hover + 0.5) / n) * 100))}%` }}>
            <div className="secondary">{bucketName(shown)}</div>
            {sources.map((s) => <div key={s.key}><Swatch colour={s.colour} />{s.label} {shown[s.key].toLocaleString()}</div>)}
          </div>
        )}
      </div>
      <div className="chart-axis" aria-hidden="true" style={{ gridTemplateColumns: `repeat(${n}, 1fr)` }}>
        {p.buckets.map((b, i) => <span key={b.start}>{(n - 1 - i) % step === 0 ? shortDate(b.start) : ""}</span>)}
      </div>
      <table className="sr-only">
        <caption>Elevations per {p.bucket_days === 1 ? "day" : "week"} by source</caption>
        <thead><tr><th>{p.bucket_days === 1 ? "Day" : "Week"}</th>{sources.map((s) => <th key={s.key}>{s.label}</th>)}</tr></thead>
        <tbody>
          {p.buckets.map((b) => (
            <tr key={b.start}><td>{bucketName(b)}</td>{sources.map((s) => <td key={s.key}>{b[s.key]}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Durations({ durations }: { durations: Period["durations"] }) {
  const longest = Math.max(1, ...durations.map((d) => d.median_allowed_seconds ?? 0));
  return (
    <ul className="durations">
      {durations.map((d) => {
        const s = sources.find((x) => x.key === d.source)!;
        const held = d.median_held_seconds, allowed = d.median_allowed_seconds;
        return (
          <li key={d.source}>
            <div className="duration-head">
              <Explain tip={s.tip}>{s.label}</Explain>
              {held === null || allowed === null || d.ended === 0
                ? <span className="secondary">None ended yet</span>
                : (
                  <span className="secondary">
                    {formatDuration(held)} of {formatDuration(allowed)},{" "}
                    {Math.round((d.given_back_early / d.ended) * 100)}% <Explain tip={tips.givenBackEarly} align="end">gave back early</Explain>
                  </span>
                )}
            </div>
            <div className="duration-track" aria-hidden="true">
              {allowed !== null && <div className="allowed" style={{ width: `${(allowed / longest) * 100}%` }} />}
              {held !== null && <div className="held" style={{ width: `${(Math.min(held, longest) / longest) * 100}%`, background: s.colour }} />}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

const sinkStates = {
  delivering: { word: "Delivering", className: "verified-text", Glyph: VerifiedGlyph },
  behind: { word: "Behind", className: "tag attention", Glyph: NotGrantedGlyph },
  failing: { word: "Failing", className: "tag denied", Glyph: NotGrantedGlyph },
  idle: { word: "Nothing sent yet", className: "secondary", Glyph: EndedGlyph },
} as const;

function HealthSection({ o }: { o: Overview }) {
  const h = o.health;
  const most = Math.max(1, ...h.agent_versions.map((v) => v.macs));
  return (
    <section aria-labelledby="overview-health">
      <h2 id="overview-health">Health</h2>
      <div className="tiles">
        <Tile title={<Explain tip={tips.agentVersions}>Agent versions</Explain>}>
          {h.agent_versions.length === 0 ? <p className="note">No Macs have checked in yet.</p> : (
            <ul className="versions">
              {h.agent_versions.map((v) => (
                <li key={v.version}>
                  <span className="data">{v.version || "Unknown"}</span>
                  <div className="version-track" aria-hidden="true">
                    <div style={{ width: `${Math.max(2, (v.macs / most) * 100)}%`, background: v.supported ? "var(--muted)" : "var(--denied)" }} />
                  </div>
                  <span>
                    {plural(v.macs, "Mac", "Macs")}
                    {!v.supported && <span className="tag denied"> <NotGrantedGlyph /> Unsupported</span>}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {h.agents_outdated > 0 && (
            <Link className="tile-link" to="/fleet?show=outdated">Show the {plural(h.agents_outdated, "Mac", "Macs")} to update</Link>
          )}
        </Tile>
        <Tile title="SIEM delivery">
          {h.sinks.length === 0 ? (
            <p className="note">No SIEM is set up. The install guide shows how to add one in the server’s settings.</p>
          ) : (
            <table className="mini">
              <thead>
                <tr>
                  <th>SIEM</th><th><Explain tip={tips.siemState}>State</Explain></th>
                  <th className="num">Waiting</th><th className="num">Last delivered</th>
                </tr>
              </thead>
              <tbody>
                {h.sinks.map((s) => {
                  const look = sinkStates[s.state];
                  return (
                    <tr key={s.sink}>
                      <td>{sinkName(s.sink)}</td>
                      <td><span className={look.className}><look.Glyph /> {look.word}</span></td>
                      <td className="num">{s.pending.toLocaleString()}</td>
                      <td className="num">{s.last_delivered_at ? relativeTime(s.last_delivered_at) : "Never"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <Link className="tile-link" to="/settings">Open Settings</Link>
        </Tile>
      </div>
    </section>
  );
}
