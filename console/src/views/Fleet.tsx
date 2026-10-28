import { Fragment, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import type { Command, Device, PermanentUse } from "../api";
import { Banner, Details, Empty, Explain, Missing, RoleNote, SearchField, Section, Segmented, Toolbar } from "../components/Chrome";
import { ClaimedGlyph, CloseIcon, ElevatedGlyph, EndedGlyph, NotGrantedGlyph, VerifiedGlyph } from "../components/Icons";
import { ConfirmSheet } from "../components/Sheet";
import { StateBadge } from "../components/StateBadge";
import { Table } from "../components/Table";
import { useApi, useCan } from "../context";
import { checkTips, persistenceCheckTip } from "../explanations";
import {
  agentOutdated, dateOnly, dateTime, expiresAfter, hasFailingCheck, integrityCheckLabel, lastCheckIn, permanentUseMethodLabel, relativeTime, revokeNotice, tamperStateLabel,
} from "../format";
import { useCommandResult } from "../useCommandResult";
import { useLoad } from "../useLoad";

/** The agent checks in every 5 minutes; three missed check-ins is worth a look. */
const STALE_MS = 15 * 60 * 1000;
const isStale = (d: Device, now = Date.now()) => now - new Date(lastCheckIn(d)).getTime() > STALE_MS;
/** The server raised agent.silent and the Mac hasn't checked in since. */
const silent = (d: Device) => d.silence?.state === "silent";
/** A tamper check failing in the newest health reading. */
const needsAttention = hasFailingCheck;
/** An admin revoked the Mac's only key: it is out of use, and stays listed only under Retired. */
const retired = (d: Device) => !!d.retired_at;
type Lifecycle = "in_use" | "retired";
/** Problems the overview links to (?show=), and how the banner names them. */
const shows = {
  attention: "Macs failing an integrity check",
  silent: "Macs not checking in",
  outdated: "Macs on an unsupported agent",
} as const;
type Show = keyof typeof shows;
/** Where and for whom a permanent admin account was used, when the agent knew. */
const permanentUseContext = (u: PermanentUse) => [
  u.on_session_of && `on ${u.on_session_of}’s session`,
  u.remote_host && `from ${u.remote_host}`,
  u.right && `for ${u.right}`,
  u.method === "sudo" && u.run_as && `as ${u.run_as}`,
].filter(Boolean).join(" · ");
/** Places the persistence snapshot couldn't read: changes there go unreported. */
const blindSpots = (d: Device) => d.persistence_unreadable ?? [];
/** Accounts named in a closed section's summary; more than this become a count. */
const SUMMARY_NAMES = 3;
const accounts = (names: string[]) => names.length <= SUMMARY_NAMES
  ? names.join(", ")
  : `${names.length} accounts`;
/** Integrity alerts shown before "Show all". */
const ALERTS_SHOWN = 3;

/** Every Mac with its versions, admin group and last check-in. */
export function FleetView() {
  const api = useApi();
  const { data, error, reload } = useLoad(() => api.devices(), [], 30_000);
  const about = useLoad(() => api.about(), []);
  const oldest = about.data?.oldest_supported_agent;
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(params.get("q") ?? "");
  const show = (params.get("show") ?? "") in shows ? params.get("show") as Show : null;
  const [selected, setSelected] = useState<string | null>(null);
  const [lifecycle, setLifecycle] = useState<Lifecycle>("in_use");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const shown = (d: Device) => show === "attention" ? needsAttention(d)
      : show === "silent" ? silent(d)
      : show === "outdated" ? !!oldest && agentOutdated(d.agent_version, oldest)
      : true;
    return (data ?? []).filter((d) => (lifecycle === "retired") === retired(d) && shown(d) && (!q || [d.serial, ...d.admin_members].some((v) => v.toLowerCase().includes(q))));
  }, [data, query, show, oldest, lifecycle]);
  const current = rows.find((d) => d.serial === selected) ?? null;
  const stale = lifecycle === "in_use" ? rows.filter((d) => isStale(d)).length : 0;
  const anyRetired = (data ?? []).some(retired);
  const noun = lifecycle === "retired" ? "retired Mac" : "Mac";

  return (
    <>
      <Toolbar title="Fleet"
        subtitle={data ? `${rows.length} ${rows.length === 1 ? noun : `${noun}s`}${stale ? `, ${stale} not checking in` : ""}` : undefined}
        onRefresh={reload}>
        <Segmented label="Show" value={lifecycle} onChange={setLifecycle} options={[
          { value: "in_use", title: "In use" }, { value: "retired", title: "Retired" },
        ]} />
        <SearchField value={query} onChange={setQuery} placeholder="Search Macs or admins" />
      </Toolbar>
      <div className={`split${current ? " with-inspector" : ""}`}>
        <div className="pane">
          {error && <Banner>{error}</Banner>}
          {show && (
            <Banner kind="info">
              Showing {shows[show]}.{" "}
              <button type="button" className="button" onClick={() => setParams({})}>Show all Macs</button>
            </Banner>
          )}
          {data && rows.length === 0 ? (
            lifecycle === "retired" && !show && !query.trim() ? (
              <Empty title="No retired Macs">A Mac is retired when you revoke its key in Enrollments.</Empty>
            ) : data.length && !show && !query.trim() && anyRetired ? (
              <Empty title="No Macs in use">Every Mac is retired. Choose Retired to see them.</Empty>
            ) : (
              <Empty title={data.length ? "No matching Macs" : "No Macs yet"}>
                {data.length ? "Try another search." : "Macs appear here after their agent first checks in."}
              </Empty>
            )
          ) : (
            <Table label="Macs" rows={rows} rowKey={(d) => d.serial} selected={selected} onSelect={setSelected}
              initialSort={{ key: "mac" }}
              columns={[
                { key: "mac", title: "Mac", sort: (d) => d.serial, render: (d) => (
                  <>
                    <span className="data">{d.serial}</span>
                    {retired(d) && (
                      <span className="tag ended" style={{ marginLeft: 8 }} title="An admin revoked this Mac’s key, so it is out of use">
                        <EndedGlyph /> Retired
                      </span>
                    )}
                    {!retired(d) && silent(d) && (
                      <span className="tag denied" style={{ marginLeft: 8 }} title="Altiward raised an alert: this Mac stopped checking in">
                        <NotGrantedGlyph /> Not checking in
                      </span>
                    )}
                    {needsAttention(d) && (
                      <span className="tag denied" style={{ marginLeft: 8 }} title="An integrity check is failing">
                        <NotGrantedGlyph /> Needs attention
                      </span>
                    )}
                    {!needsAttention(d) && blindSpots(d).length > 0 && (
                      <span className="tag attention" style={{ marginLeft: 8 }} title="The agent can't read some places it checks for persistence">
                        <NotGrantedGlyph /> Partly checked
                      </span>
                    )}
                  </>
                ) },
                { key: "checkin", title: "Last check-in", sort: (d) => new Date(lastCheckIn(d)).getTime(), render: (d) => (
                  <>{relativeTime(lastCheckIn(d))}{!retired(d) && isStale(d) && <span className="tag attention" style={{ marginLeft: 8 }}>Late</span>}</>
                ) },
                { key: "admins", title: "Admins", sort: (d) => d.admin_members.length,
                  render: (d) => d.admin_members.length ? <AdminNames device={d} /> : <span className="secondary">None</span> },
                { key: "macos", title: "macOS", sort: (d) => d.os_version, render: (d) => d.os_version, drop: 2 },
                { key: "agent", title: "Agent", sort: (d) => d.agent_version, render: (d) => (
                  <>
                    {d.agent_version}
                    {oldest && agentOutdated(d.agent_version, oldest) && (
                      <span className="tag attention" style={{ marginLeft: 8 }}
                        title={`Older than ${oldest}, the oldest agent this server supports. Deploy the current agent through your MDM.`}>
                        <ClaimedGlyph /> Agent outdated
                      </span>
                    )}
                  </>
                ) },
                { key: "privileges", title: "Privileges", sort: (d) => d.privileges_version ?? "", drop: 2,
                  render: (d) => d.privileges_version ?? <span className="secondary">Not installed</span> },
                { key: "queue", title: "Queued", align: "right", sort: (d) => d.queue_depth ?? 0, drop: 1,
                  render: (d) => d.queue_depth == null
                    ? <Missing>Not reported</Missing>
                    : <span className="data">{String(d.queue_depth)}</span> },
              ]} />
          )}
        </div>
        {current && <DeviceInspector device={current} severities={about.data?.tamper_severities} onClose={() => setSelected(null)} />}
      </div>
    </>
  );
}

/** Elevated users first; permanent admins after, quieter, since they are expected. */
function AdminNames({ device: d }: { device: Device }) {
  const permanent = new Set(d.permanent_admins ?? []);
  const elevated = d.admin_members.filter((u) => !permanent.has(u));
  const standing = d.admin_members.filter((u) => permanent.has(u));
  return (
    <>
      {elevated.join(", ")}
      {standing.length > 0 && <span className="secondary">{elevated.length ? ", " : ""}{standing.join(", ")}</span>}
    </>
  );
}

const yesNo = (v: unknown) => (v === true ? "Yes" : v === false ? "No" : <Missing>Not reported</Missing>);

/** The severity a failing check is exported with. The server exports a check it doesn't
 *  know as High, so one missing from `severities` is High too. */
function checkSeverity(check: string, severities: Record<string, string> | undefined): string | undefined {
  if (!severities) return undefined;
  return severities[check] ?? "High";
}

/** When a retired Mac left use, and when its history goes: history goes once the Mac's last
 *  check-in is older than the period, so that day is the last check-in plus the period. */
function RetiredNote({ device: d }: { device: Device }) {
  const api = useApi();
  const { data } = useLoad(() => api.retention(), []);
  const policy = data?.history;
  const removal = policy && policy.days > 0 && !policy.kept_for_good
    ? new Date(new Date(lastCheckIn(d)).getTime() + policy.days * 86_400_000).toISOString()
    : null;
  // While the SIEM's coverage or the admin group backfill holds expiry back, the Mac may be
  // kept past that date, so it is the earliest, not the day.
  const held = !!policy && (!!policy.held_before || policy.waiting_for_backfill);
  return (
    <>
      <p className="lede" title={dateTime(d.retired_at)}><span className="tag ended"><EndedGlyph /> Retired</span> {dateOnly(d.retired_at)}</p>
      {policy && (
        <p className="lede">
          {!removal ? "History is kept for good."
            : held ? `History is removed no earlier than ${dateOnly(removal)}.`
            : `History is removed ${dateOnly(removal)}.`}
        </p>
      )}
    </>
  );
}

function DeviceInspector({ device: d, severities, onClose }: {
  device: Device;
  severities: Record<string, string> | undefined;
  onClose: () => void;
}) {
  const api = useApi();
  const [target, setTarget] = useState<string | null | undefined>(undefined); // undefined: no sheet; null: everyone
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ kind: "error" | "info"; text: string } | null>(null);
  const [sent, setSent] = useState<Command | null>(null);
  useCommandResult(sent, (c) => {
    setSent(null);
    setNotice(revokeNotice(c, c.user ?? undefined));
  });
  const p = d.privileges ?? {};
  const isRetired = retired(d);
  const permanent = new Set(d.permanent_admins ?? []);

  // A retired Mac has no key, so a revoke could never reach it.
  const canRevoke = useCan("operator") && !isRetired;
  async function revoke() {
    setBusy(true);
    try {
      setSent(await api.revokeDevice(d.serial, target ?? undefined));
      setNotice({ kind: "info", text: `Revoke sent to ${d.serial}. It usually applies within a few seconds while the Mac is online, or when it next connects. Permanent admins stay.` });
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
      setTarget(undefined);
    }
  }

  return (
    <aside className="inspector" aria-label="Mac details">
      <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
        <div style={{ flex: 1 }}>
          <h2 className="data" style={{ fontSize: 18, lineHeight: "24px" }}>{d.serial}</h2>
          <p className="lede">macOS {d.os_version}. Last check-in {relativeTime(lastCheckIn(d)).toLowerCase()}.</p>
          {isRetired && <RetiredNote device={d} />}
          {!isRetired && silent(d) && (
            <p className="lede" title={dateTime(d.silence!.at)}>
              <span className="tag denied"><NotGrantedGlyph /> Not checking in</span>{" "}
              Alert raised {relativeTime(d.silence!.at).toLowerCase()}. The agent may have been removed, the Mac is off, or it can’t reach the agent hostname from where it is.
            </p>
          )}
          {d.admin_members.some((u) => !permanent.has(u)) && (
            <div className="badges"><StateBadge state="elevated" explain /></div>
          )}
        </div>
        <button type="button" className="button icon-button" aria-label="Close details" onClick={onClose}><CloseIcon /></button>
      </div>
      {!isRetired && d.admin_members.some((u) => !permanent.has(u)) && (canRevoke ? (
        <div className="actions">
          <button type="button" className="button destructive" onClick={() => setTarget(null)}>Revoke all admin rights…</button>
        </div>
      ) : <RoleNote>Revoking admin rights needs the operator role.</RoleNote>)}
      {notice && <div style={{ margin: "8px -16px 0" }}><Banner kind={notice.kind}>{notice.text}</Banner></div>}

      <Fragment key={d.serial}>
      <Section id="admin-group" title="Admin group" defaultOpen
        summary={d.admin_members.length === 0 ? "No one" : accounts(d.admin_members)}>
        <div className="box">
          {d.admin_members.length === 0 && <p className="secondary" style={{ padding: "6px 0" }}>No one is an admin.</p>}
          <dl>
            {d.admin_members.map((u) => [
              <dt key={`${u}-t`} style={{ color: "var(--label)" }}>{u}</dt>,
              <dd key={`${u}-d`}>
                {permanent.has(u) ? (
                  <span className="secondary" title="Altiward never removes permanent admins">Permanent</span>
                ) : !canRevoke ? null : (
                  <button type="button" className="button destructive" aria-label={`Revoke ${u}…`} onClick={() => setTarget(u)}>Revoke…</button>
                )}
              </dd>,
            ])}
          </dl>
        </div>
      </Section>

      {d.permanent_admins && (
        <Section id="permanent-admins" title="Permanent admins"
          summary={d.permanent_admins.length === 0 ? "None set" : accounts(d.permanent_admins)}
          attention={(d.recent_permanent_uses ?? []).some((u) => u.state === "started")}>
          <div className="box">
            {d.permanent_admins.length === 0
              ? <p className="secondary" style={{ padding: "6px 0" }}>None set.</p>
              : (
                <dl>
                  {d.permanent_admins.map((u) => [
                    <dt key={`${u}-t`} style={{ color: "var(--label)" }}>{u}</dt>,
                    <dd key={`${u}-d`}><span className="secondary">{d.admin_members.includes(u) ? "Admin now" : "Not an admin now"}</span></dd>,
                  ])}
                </dl>
              )}
          </div>
          {(d.recent_permanent_uses ?? []).length > 0 && (
            <div className="box" style={{ marginTop: 8 }}>
              <ul className="entries" aria-label="Recent use of permanent admins">
                {(d.recent_permanent_uses ?? []).slice(0, 10).map((u) => (
                  <li key={u.use_id}>
                    <span>{u.account}{u.count > 1 && ` ×${u.count}`}</span>
                    {u.state === "single"
                      ? <span className="secondary" title={dateTime(u.started_at)}>{relativeTime(u.started_at).toLowerCase()}</span>
                      : u.state === "started"
                        ? <span className="tag attention"><ElevatedGlyph /> Signed in now</span>
                        : <span className="secondary"><EndedGlyph /> Ended</span>}
                    <span className="detail">
                      {[permanentUseMethodLabel(u.method), permanentUseContext(u)].filter(Boolean).join(" · ")}
                    </span>
                    {u.state === "started" && (
                      <span className="detail secondary" title={dateTime(u.started_at)}>Since {relativeTime(u.started_at).toLowerCase()}</span>
                    )}
                    {u.state === "ended" && (
                      <span className="detail secondary">{dateTime(u.started_at)} to {dateTime(u.ended_at)}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="role-note">
            From the Mac’s configuration profile. Change them in your MDM: Altiward reports this setting made any other
            way as tampering, and never removes these accounts’ admin rights. It records each time someone uses one.
          </p>
        </Section>
      )}

      {(d.integrity || d.persistence_unreadable || (d.recent_tamper ?? []).length > 0) && (
        <Section id="integrity" title="Integrity" summary={<IntegritySummary device={d} />}
          attention={hasFailingCheck(d) || blindSpots(d).length > 0}>
          {(d.integrity || d.persistence_unreadable) && (
            <div className="box">
              <dl>
                {Object.entries(d.integrity ?? {}).sort(([a], [b]) => a.localeCompare(b)).map(([check, passing]) => [
                  <dt key={`${check}-t`}>
                    {checkTips[check] ? <Explain tip={checkTips[check]}>{integrityCheckLabel(check)}</Explain> : integrityCheckLabel(check)}
                  </dt>,
                  <dd key={`${check}-d`}>
                    {passing
                      ? <span className="secondary"><VerifiedGlyph /> Passing</span>
                      : <>
                          <span className="tag denied"><NotGrantedGlyph /> Failing</span>
                          {checkSeverity(check, severities) && (
                            <div className="secondary" title="The severity your SIEM receives for this check">
                              {checkSeverity(check, severities)} severity
                            </div>
                          )}
                        </>}
                  </dd>,
                ])}
                {d.persistence_unreadable && [
                  <dt key="persistence-t"><Explain tip={persistenceCheckTip}>Persistence check</Explain></dt>,
                  <dd key="persistence-d">
                    {d.persistence_unreadable.length === 0
                      ? <span className="secondary"><VerifiedGlyph /> Reads every place</span>
                      : <>
                          <span className="tag attention"><NotGrantedGlyph /> Can’t read {d.persistence_unreadable.length === 1 ? "1 place" : `${d.persistence_unreadable.length} places`}</span>
                          {d.persistence_unreadable.map((p) => <div key={p} className="data" style={{ overflowWrap: "anywhere" }}>{p}</div>)}
                        </>}
                  </dd>,
                ]}
              </dl>
            </div>
          )}
          {(d.recent_tamper ?? []).length > 0 && <IntegrityAlerts device={d} />}
        </Section>
      )}

      <Section id="agent" title="Agent" summary={d.agent_version}>
        <Details rows={[
          ["Agent version", d.agent_version],
          ["Hardware UUID", <span key="hw" className="data">{d.hardware_uuid}</span>],
          ["First seen", dateTime(d.first_seen_at)],
          ["Last check-in", dateTime(lastCheckIn(d))],
          ["Events queued", d.queue_depth == null ? <Missing key="queued">Not reported</Missing> : String(d.queue_depth)],
        ]} />
      </Section>

      <Section id="privileges" title="SAP Privileges" summary={d.privileges_version ?? "Not installed"}>
        <Details rows={[
          ["Version", d.privileges_version ?? "Not installed"],
          ["Reports to Altiward", yesNo(p.post_change_hook_configured)],
          ["Passes the reason", yesNo(p.pass_reason_to_executable)],
          ["Expires after", expiresAfter(p) ?? <Missing key="expires">Not set</Missing>],
          ["Tamper protection", yesNo(p.system_extension_enabled)],
          ["Daily admin budget", p.admin_budget_minutes != null
            ? `${p.admin_budget_minutes} min` : <Missing key="budget">Not set</Missing>],
        ]} />
      </Section>
      </Fragment>

      {target !== undefined && (
        <ConfirmSheet
          title={target ? `Revoke admin rights for ${target}?` : `Revoke all admin rights on ${d.serial}?`}
          message={target
            ? `${target} loses admin rights on ${d.serial}, usually within a few seconds while the Mac is online, or when it next connects.`
            : "Everyone except permanent admins loses admin rights, usually within a few seconds while the Mac is online, or when it next connects."}
          confirm="Revoke" destructive busy={busy} onConfirm={revoke} onCancel={() => setTarget(undefined)} />
      )}
    </aside>
  );
}

/** The Integrity section's summary while closed: how many checks fail, or that all pass. */
function IntegritySummary({ device: d }: { device: Device }) {
  const checks = Object.values(d.integrity ?? {});
  const failing = checks.filter((passing) => !passing).length;
  const unread = blindSpots(d).length;
  if (failing > 0) return <span className="tag denied"><NotGrantedGlyph /> {failing} failing</span>;
  if (unread > 0) return <span className="tag attention"><NotGrantedGlyph /> Can’t read {unread === 1 ? "1 place" : `${unread} places`}</span>;
  const total = checks.length + (d.persistence_unreadable ? 1 : 0);
  if (total === 0) return null;
  return <><VerifiedGlyph /> {total === 1 ? "Passing" : `All ${total} passing`}</>;
}

/** The newest integrity alerts, with the rest of the last ten behind "Show all". */
function IntegrityAlerts({ device: d }: { device: Device }) {
  const [all, setAll] = useState(false);
  const alerts = (d.recent_tamper ?? []).slice(0, 10);
  const shown = all ? alerts : alerts.slice(0, ALERTS_SHOWN);
  return (
    <div className="box" style={{ marginTop: 8 }}>
      <ul className="entries" aria-label="Recent integrity alerts">
        {shown.map((a) => (
          <li key={a.event_id}>
            <span>{integrityCheckLabel(a.check)}</span>
            <span className="secondary" title={dateTime(a.at)}>{relativeTime(a.at).toLowerCase()}</span>
            <span className="detail">{tamperStateLabel(a.state, a.check)}{a.problem && `: ${a.problem}`}</span>
          </li>
        ))}
      </ul>
      {alerts.length > ALERTS_SHOWN && (
        <div className="more">
          <button type="button" className="button" aria-expanded={all} onClick={() => setAll(!all)}>
            {all ? "Show fewer" : `Show all ${alerts.length}`}
          </button>
        </div>
      )}
    </div>
  );
}
