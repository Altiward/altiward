import { useState } from "react";
import type { Command, Session, TimelineEvent } from "../api";
import { useApi, useCan } from "../context";
import { flagTips, sourceTips } from "../explanations";
import {
  dateTime, endReasonLabel, flagLabel, formatDuration, persistenceLines, revokeNotice, sessionState, sourceLabel,
} from "../format";
import { useCommandResult } from "../useCommandResult";
import { useLoad } from "../useLoad";
import { Banner, Details, Explain, Missing, RoleNote } from "./Chrome";
import { CloseIcon, ElevatedGlyph, EndedGlyph, NotGrantedGlyph } from "./Icons";
import { ConfirmSheet } from "./Sheet";
import { StateBadge } from "./StateBadge";

/** The install guide's step that sets PermanentAdmins in the agent's profile. */
const PERMANENT_ADMINS_GUIDE = "https://github.com/Altiward/altiward/blob/main/docs/install.md#2-deploy-the-agent";

const eventLabels: Record<string, string> = {
  "elevation.granted": "Granted",
  "elevation.revoked": "Revoked",
  "elevation.expired_enforced": "Removed at expiry",
  "elevation.overdue": "Past expiry",
  "admin.out_of_band": "Found without a grant",
  "admin.out_of_band_removed": "Removed without a grant",
  "persistence.detected": "New persistence",
  "agent.admin_group": "Admin group sent to the SIEM",
};

/** The timeline's name for an event; an end that removed nothing doesn't say Revoked. */
function eventLabel(e: TimelineEvent): string {
  if (e.type === "elevation.revoked" && e.detail.trigger === "permanent_admin") return "Now a permanent admin";
  if (e.type === "elevation.revoked" && e.detail.trigger === "privileges_grant") return "Replaced by a Privileges grant";
  return eventLabels[e.type] ?? e.type;
}

function eventNote(e: TimelineEvent): string | null {
  const d = e.detail;
  if (e.type === "admin.out_of_band_removed") {
    if (typeof d.grace_seconds !== "number" || !Number.isFinite(d.grace_seconds)) return null;
    const minutes = Math.round((d.grace_seconds / 60) * 10) / 10;
    return `After ${minutes} ${minutes === 1 ? "minute" : "minutes"} without a grant`;
  }
  if (d.trigger === "permanent_admin") return "Rights kept, no longer unexplained";
  if (d.trigger === "privileges_grant") return "Rights kept, now under a Privileges grant";
  if (d.trigger === "command") return "From the console";
  if (d.trigger === "heartbeat" && e.type === "elevation.revoked") return "Seen by the agent";
  if (e.type === "elevation.granted") {
    if (d.privileges_log === "confirmed") return "Confirmed by Privileges’ log";
    if (d.privileges_log === "not_confirmed") return "Not confirmed by Privileges’ log";
  }
  if (d.trigger === "privileges_renewal") return "Renewed in Privileges";
  if (d.renewed === true) return "Renewal";
  if (d.verified === false) return "Claim didn’t match the admin group";
  if (e.type === "elevation.overdue" && d.enforcement_failed === true) return "Couldn’t remove rights";
  if (e.type === "persistence.detected") return null; // listed below the event
  if (e.type === "admin.out_of_band") {
    // Logged by Privileges' system extension, when it is on.
    const by = (d.instigator as { executable?: string } | undefined)?.executable;
    return by ? `Added by ${by}` : null;
  }
  return e.elevation?.reason ?? null;
}

/** Elevated while rights are held, Without a grant for rights nobody granted, Ended after. */
function EventGlyph({ type }: { type: string }) {
  if (type === "admin.out_of_band" || type === "persistence.detected") return <span style={{ color: "var(--denied)" }}><NotGrantedGlyph /></span>;
  if (type === "elevation.granted" || type === "elevation.overdue")
    return <span style={{ color: "var(--elevated-ink)" }}><ElevatedGlyph /></span>;
  return <span className="secondary"><EndedGlyph /></span>;
}

export function displayName(s: Pick<Session, "upn" | "local_user">) {
  return s.upn ?? s.local_user;
}

export function SessionInspector({ session, onClose, onChanged }: {
  session: Session; onClose: () => void; onChanged?: () => void;
}) {
  const api = useApi();
  const { data } = useLoad(() => api.session(session.session_id), [session.session_id]);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ kind: "error" | "info"; text: string } | null>(null);
  const [sent, setSent] = useState<Command | null>(null);
  const name = displayName(session);
  useCommandResult(sent, (c) => {
    setSent(null);
    setNotice(revokeNotice(c, name));
    onChanged?.();
  });

  const canRevoke = useCan("operator");
  async function revoke() {
    setBusy(true);
    try {
      setSent(await api.revokeSession(session.session_id));
      setNotice({ kind: "info", text: `Revoke sent to ${session.device_serial}. It usually applies within a few seconds while the Mac is online, or when it next connects.` });
      onChanged?.();
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  }

  const flags = session.flags.filter((f) => flagLabel(f) != null);
  return (
    <aside className="inspector" aria-label="Session details">
      <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h2>{name}</h2>
          <p className="lede">{session.upn ? `${session.local_user} on ` : ""}<span className="data">{session.device_serial}</span></p>
          <div className="badges">
            <StateBadge state={sessionState(session)} explain />
            {session.source !== "out_of_band" && <StateBadge state={session.verified ? "verified" : "claimed"} explain />}
          </div>
        </div>
        <button type="button" className="button icon-button" aria-label="Close details" onClick={onClose}><CloseIcon /></button>
      </div>

      {session.open && session.permanent_admin && (
        <p className="role-note">{session.local_user} is a permanent admin on this Mac, so Altiward doesn’t remove their rights.</p>
      )}
      {session.open && !session.permanent_admin && canRevoke && (
        <div className="actions">
          <button type="button" className="button destructive" onClick={() => setConfirming(true)}>Revoke admin rights…</button>
        </div>
      )}
      {session.open && !session.permanent_admin && !canRevoke && <RoleNote>Revoking admin rights needs the operator role.</RoleNote>}
      {session.open && !session.permanent_admin && session.source === "out_of_band" && (
        <p className="role-note">
          If {session.local_user} is this Mac’s managed admin account (LAPS) or another standing IT account, add it
          to <code>PermanentAdmins</code> in the Altiward profile in your MDM (<a href={PERMANENT_ADMINS_GUIDE}
          target="_blank" rel="noreferrer">how</a>). Altiward can’t tell a managed account from one made to look like
          it, so your MDM decides.
        </p>
      )}
      {notice && <div style={{ margin: "8px -16px 0" }}><Banner kind={notice.kind}>{notice.text}</Banner></div>}

      <div className="group">
        <Details rows={[
          ["State", endReasonLabel(session.end_reason)],
          ["Source", sourceTips[session.source]
            ? <Explain tip={sourceTips[session.source]} align="end">{sourceLabel(session.source)}</Explain>
            : sourceLabel(session.source)],
          ["Started", dateTime(session.started_at)],
          ["Expires", session.expires_at ? dateTime(session.expires_at) : <Missing key="expires">No expiry known</Missing>],
          ["Ended", session.ended_at ? dateTime(session.ended_at) : <Missing key="ended">Not yet</Missing>],
          ["Time used", session.actual_seconds == null
            ? <Missing key="used">Unknown</Missing>
            : <span className="data">{formatDuration(session.actual_seconds)}</span>],
          ["Renewals", String(session.renewals)],
          ["Reason", session.reason ?? <Missing key="reason">None given</Missing>],
        ]} />
      </div>

      {flags.length > 0 && (
        <div className="group">
          <h3>Needs attention</h3>
          <div className="box" style={{ padding: "8px 10px" }}>
            {flags.map((f) => (
              <div key={f}>
                {flagTips[f]
                  ? <Explain tip={flagTips[f]} bare><span className="tag attention">{flagLabel(f)}</span></Explain>
                  : <span className="tag attention">{flagLabel(f)}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="group">
        <h3>Timeline</h3>
        <div className="box">
          <ol className="timeline">
            {(data?.events ?? []).map((e) => (
              <li key={e.event_id}>
                <EventGlyph type={e.type} />
                <div>
                  <div>{eventLabel(e)}</div>
                  <div className="when">{dateTime(e.timestamp)}{e.delayed ? ", sent late" : ""}</div>
                  {eventNote(e) && <div className="secondary">{eventNote(e)}</div>}
                  {e.type === "persistence.detected" && (
                    <ul className="findings">
                      {persistenceLines(e.detail).map((line, i) => <li key={i} className="data">{line}</li>)}
                    </ul>
                  )}
                </div>
              </li>
            ))}
            {data && data.events.length === 0 && <li><span /><span className="secondary">No events yet.</span></li>}
          </ol>
        </div>
      </div>

      {confirming && (
        <ConfirmSheet
          title={`Revoke admin rights for ${name}?`}
          message={`${name} loses admin rights on ${session.device_serial}, usually within a few seconds while the Mac is online, or when it next connects.`}
          confirm="Revoke" destructive busy={busy}
          onConfirm={revoke} onCancel={() => setConfirming(false)}
        />
      )}
    </aside>
  );
}
