import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import type { Command, Device } from "../api";
import { Banner, Details, Empty, Explain, RoleNote, SearchField, Toolbar } from "../components/Chrome";
import { ClaimedGlyph, CloseIcon, NotGrantedGlyph, VerifiedGlyph } from "../components/Icons";
import { ConfirmSheet } from "../components/Sheet";
import { StateBadge } from "../components/StateBadge";
import { Table } from "../components/Table";
import { useApi, useCan } from "../context";
import { checkTips, persistenceCheckTip } from "../explanations";
import {
  agentOutdated, dateTime, integrityCheckLabel, relativeTime, revokeNotice, tamperStateLabel,
} from "../format";
import { useCommandResult } from "../useCommandResult";
import { useLoad } from "../useLoad";

/** The agent checks in every 5 minutes; three missed check-ins is worth a look. */
const STALE_MS = 15 * 60 * 1000;
/** By the server's clock when known, so a Mac whose clock is wrong doesn't look late. */
const lastCheckIn = (d: Device) => d.last_received_at ?? d.last_health_at ?? d.last_seen_at;
const isStale = (d: Device, now = Date.now()) => now - new Date(lastCheckIn(d)).getTime() > STALE_MS;
/** The server raised agent.silent and the Mac hasn't checked in since. */
const silent = (d: Device) => d.silence?.state === "silent";
/** A tamper check failing in the newest health reading. */
const needsAttention = (d: Device) => Object.values(d.integrity ?? {}).some((passing) => !passing);
/** Problems the overview links to (?show=), and how the banner names them. */
const shows = {
  attention: "Macs failing an integrity check",
  silent: "Macs not checking in",
  outdated: "Macs on an unsupported agent",
} as const;
type Show = keyof typeof shows;
/** Places the persistence snapshot couldn't read: changes there go unreported. */
const blindSpots = (d: Device) => d.persistence_unreadable ?? [];

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

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const shown = (d: Device) => show === "attention" ? needsAttention(d)
      : show === "silent" ? silent(d)
      : show === "outdated" ? !!oldest && agentOutdated(d.agent_version, oldest)
      : true;
    return (data ?? []).filter((d) => shown(d) && (!q || [d.serial, ...d.admin_members].some((v) => v.toLowerCase().includes(q))));
  }, [data, query, show, oldest]);
  const current = rows.find((d) => d.serial === selected) ?? null;
  const stale = rows.filter((d) => isStale(d)).length;

  return (
    <>
      <Toolbar title="Fleet"
        subtitle={data ? `${rows.length} ${rows.length === 1 ? "Mac" : "Macs"}${stale ? `, ${stale} not checking in` : ""}` : undefined}
        onRefresh={reload}>
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
            <Empty title={data.length ? "No matching Macs" : "No Macs yet"}>
              {data.length ? "Try another search." : "Macs appear here after their agent first checks in."}
            </Empty>
          ) : (
            <Table label="Macs" rows={rows} rowKey={(d) => d.serial} selected={selected} onSelect={setSelected}
              initialSort={{ key: "mac" }}
              columns={[
                { key: "mac", title: "Mac", sort: (d) => d.serial, render: (d) => (
                  <>
                    <span className="data">{d.serial}</span>
                    {silent(d) && (
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
                  <>{relativeTime(lastCheckIn(d))}{isStale(d) && <span className="tag attention" style={{ marginLeft: 8 }}>Late</span>}</>
                ) },
                { key: "admins", title: "Admins", sort: (d) => d.admin_members.length,
                  render: (d) => d.admin_members.length ? <AdminNames device={d} /> : <span className="secondary">None</span> },
                { key: "macos", title: "macOS", sort: (d) => d.os_version, render: (d) => d.os_version },
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
                { key: "privileges", title: "Privileges", sort: (d) => d.privileges_version ?? "",
                  render: (d) => d.privileges_version ?? <span className="secondary">Not installed</span> },
                { key: "queue", title: "Queued", align: "right", sort: (d) => d.queue_depth ?? 0,
                  render: (d) => <span className="data">{d.queue_depth == null ? "—" : String(d.queue_depth)}</span> },
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

const yesNo = (v: unknown) => (v === true ? "Yes" : v === false ? "No" : "—");

/** The severity a failing check is exported with. The server exports a check it doesn't
 *  know as High, so one missing from `severities` is High too. */
function checkSeverity(check: string, severities: Record<string, string> | undefined): string | undefined {
  if (!severities) return undefined;
  return severities[check] ?? "High";
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
  const permanent = new Set(d.permanent_admins ?? []);

  const canRevoke = useCan("operator");
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
          {silent(d) && (
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
      {d.admin_members.some((u) => !permanent.has(u)) && (canRevoke ? (
        <div className="actions">
          <button type="button" className="button destructive" onClick={() => setTarget(null)}>Revoke all admin rights…</button>
        </div>
      ) : <RoleNote>Revoking admin rights needs the operator role.</RoleNote>)}
      {notice && <div style={{ margin: "8px -16px 0" }}><Banner kind={notice.kind}>{notice.text}</Banner></div>}

      <div className="group" role="group" aria-labelledby="admin-group-title">
        <h3 id="admin-group-title">Admin group</h3>
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
      </div>

      {d.permanent_admins && (
        <div className="group" role="group" aria-labelledby="permanent-admins-title">
          <h3 id="permanent-admins-title">Permanent admins</h3>
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
          <p className="role-note">
            From the Mac’s configuration profile. Change them in your MDM: Altiward reports this setting made any other
            way as tampering, and never removes these accounts’ admin rights.
          </p>
        </div>
      )}

      {(d.integrity || d.persistence_unreadable || (d.recent_tamper ?? []).length > 0) && (
        <div className="group" role="group" aria-labelledby="integrity-title">
          <h3 id="integrity-title">Integrity</h3>
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
          {(d.recent_tamper ?? []).length > 0 && (
            <div className="box" style={{ marginTop: 8 }}>
              <ul className="entries" aria-label="Recent integrity alerts">
                {(d.recent_tamper ?? []).slice(0, 10).map((a) => (
                  <li key={a.event_id}>
                    <span>{integrityCheckLabel(a.check)}</span>
                    <span className="secondary" title={dateTime(a.at)}>{relativeTime(a.at).toLowerCase()}</span>
                    <span className="detail">{tamperStateLabel(a.state, a.check)}{a.problem && `: ${a.problem}`}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="group">
        <h3>Agent</h3>
        <Details rows={[
          ["Agent version", d.agent_version],
          ["Hardware UUID", <span key="hw" className="data">{d.hardware_uuid}</span>],
          ["First seen", dateTime(d.first_seen_at)],
          ["Last check-in", dateTime(lastCheckIn(d))],
          ["Events queued", d.queue_depth == null ? "—" : String(d.queue_depth)],
        ]} />
      </div>

      <div className="group">
        <h3>SAP Privileges</h3>
        <Details rows={[
          ["Version", d.privileges_version ?? "Not installed"],
          ["Reports to Altiward", yesNo(p.post_change_hook_configured)],
          ["Passes the reason", yesNo(p.pass_reason_to_executable)],
          ["Expires after", p.expiration_interval_minutes != null ? `${p.expiration_interval_minutes} min` : "—"],
          ["Tamper protection", yesNo(p.system_extension_enabled)],
        ]} />
      </div>

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
