import { type JSX, useMemo, useState } from "react";
import { ApiError, type CredentialStatus, type Enrollment, type KeyStorage } from "../api";
import { Banner, Details, Empty, Explain, Missing, RoleNote, SearchField, Segmented, Toolbar } from "../components/Chrome";
import { Fingerprint } from "../components/Fingerprint";
import { AttentionGlyph, ChipGlyph, CloseIcon, EndedGlyph, FileGlyph, RotatedGlyph } from "../components/Icons";
import { ConfirmSheet } from "../components/Sheet";
import { StateBadge } from "../components/StateBadge";
import { Table } from "../components/Table";
import { useApi, useCan } from "../context";
import { explanations } from "../explanations";
import { dateTime, lastCheckIn, relativeTime } from "../format";
import { useLoad } from "../useLoad";

type Filter = CredentialStatus | "rotated" | "all";
const statusTitle: Record<CredentialStatus, string> = { active: "Active", pending: "Waiting for approval", revoked: "Revoked" };
const statusLook = { active: "verified", pending: "claimed", revoked: "ended" } as const;
/** A key replaced by rotation is revoked too, but says "Rotated": nobody revoked it, and there is
 *  nothing to do about it. */
const isRotated = (e: Enrollment) => e.status === "revoked" && !!e.rotated_to;
/** Rotated keys have a filter of their own, so Revoked lists only keys someone revoked. */
const shows = (filter: Filter, e: Enrollment) =>
  filter === "all" || (filter === "rotated" ? isRotated(e) : e.status === filter && !isRotated(e));
const Status = ({ enrollment: e, explain }: { enrollment: Enrollment; explain?: boolean }) => isRotated(e)
  ? explain
    ? <Explain tip={explanations.rotated} bare><StateBadge state="ended" label="Rotated" glyph={RotatedGlyph} /></Explain>
    : <StateBadge state="ended" label="Rotated" glyph={RotatedGlyph} />
  : <StateBadge state={statusLook[e.status]} label={statusTitle[e.status]} />;

/** Another key of the same Mac, named by its fingerprint: following it shows that key. */
function KeyLink({ enrollment, onFollow }: { enrollment: Enrollment; onFollow: (deviceID: string) => void }) {
  return (
    <button type="button" className="link data" onClick={() => onFollow(enrollment.device_id)}>
      <Fingerprint publicKey={enrollment.public_key} />
    </button>
  );
}

/** Where the Mac says its key is kept. Plain, not a coloured badge: it's the Mac's claim. */
const keyStorageLook: Record<KeyStorage, [string, () => JSX.Element]> = {
  secure_enclave: ["Secure Enclave", ChipGlyph], software: ["File", FileGlyph], "": ["Not reported", EndedGlyph],
};
function KeyKeptIn({ storage }: { storage: KeyStorage }) {
  const [word, Glyph] = keyStorageLook[storage] ?? keyStorageLook[""];
  return <span className="key-storage"><Glyph />{word}</span>;
}

/** Device credentials: approve re-enrollments, revoke lost Macs. */
export function EnrollmentsView({ onChanged }: { onChanged?: () => void }) {
  const api = useApi();
  const { data, error, reload } = useLoad(() => api.enrollments(), [], 30_000);
  const [evidenceVersion, setEvidenceVersion] = useState(0);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  // Lives here, not in the inspector: an approved row can leave the filtered list.
  const [done, setDone] = useState<string | null>(null);
  // The key in use, when a revoke named a key that has since been rotated.
  const [rotatedTo, setRotatedTo] = useState<string | null>(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data ?? []).filter((e) => shows(filter, e) && (!q || e.serial.toLowerCase().includes(q) || e.token.toLowerCase().includes(q)));
  }, [data, filter, query]);
  const current = rows.find((e) => e.device_id === selected) ?? null;
  const pending = (data ?? []).filter((e) => e.status === "pending").length;
  const byID = (id: string | undefined) => (data ?? []).find((e) => e.device_id === id);
  // The key in use after a rotated key: the end of its rotations, when that key is active.
  const inUseAfter = (e: Enrollment) => {
    const seen = new Set([e.device_id]);
    let key = byID(e.rotated_to);
    while (key?.rotated_to && !seen.has(key.device_id)) {
      seen.add(key.device_id);
      key = byID(key.rotated_to);
    }
    return key?.status === "active" ? key : undefined;
  };
  const keyInUse = byID(rotatedTo ?? undefined);
  // A key may be hidden by the filter or the search: show them all, then select it.
  const follow = (id: string) => { setFilter("all"); setQuery(""); setRotatedTo(null); setSelected(id); };

  return (
    <>
      <Toolbar title="Enrollments" subtitle={pending ? `${pending} waiting for approval` : undefined} onRefresh={() => { void reload(); setEvidenceVersion((v) => v + 1); }}>
        <Segmented label="Show" value={filter} onChange={setFilter} options={[
          { value: "all", title: "All" }, { value: "pending", title: "Waiting" },
          { value: "active", title: "Active" }, { value: "revoked", title: "Revoked" },
          { value: "rotated", title: "Rotated" },
        ]} />
        <SearchField value={query} onChange={setQuery} placeholder="Search serial numbers and tokens" />
      </Toolbar>
      <div className={`split${current ? " with-inspector" : ""}`}>
        <div className="pane">
          {error && <Banner>{error}</Banner>}
          {done && <Banner kind="info">{done}</Banner>}
          {keyInUse && (
            <Banner>
              That key was rotated, so it can’t be revoked. The key in use is <KeyLink enrollment={keyInUse} onFollow={follow} />.
            </Banner>
          )}
          {data && rows.length === 0 ? (
            <Empty title={data.length ? "No matching enrollments" : "No Macs enrolled yet"}>
              {data.length ? "Try another filter." : "A Mac enrols the first time its agent reaches the server with your enrolment token."}
            </Empty>
          ) : (
            <Table label="Enrollments" rows={rows} rowKey={(e) => e.device_id} selected={selected} onSelect={setSelected}
              initialSort={{ key: "enrolled", descending: true }}
              columns={[
                { key: "mac", title: "Mac", sort: (e) => e.serial, render: (e) => <span className="data">{e.serial}</span> },
                { key: "status", title: "Status", sort: (e) => e.status, render: (e) => <Status enrollment={e} /> },
                // Where the key is kept goes under the fingerprint: a column of its own leaves the
                // dates no room beside the inspector.
                { key: "key", title: "Key", render: (e) => (
                  <span className="key-cell">
                    <span className="data secondary"><Fingerprint publicKey={e.public_key} /></span>
                    <span className="secondary small"><KeyKeptIn storage={e.key_storage} /></span>
                  </span>
                ) },
                { key: "enrolled", title: "Enrolled", sort: (e) => new Date(e.created_at).getTime(),
                  render: (e) => <span className="secondary small">{dateTime(e.created_at)}</span> },
              ]} />
          )}
        </div>
        {current && (
          <EnrollmentInspector enrollment={current} onClose={() => setSelected(null)} evidenceVersion={evidenceVersion}
            active={(data ?? []).find((e) => e.serial === current.serial && e.device_id !== current.device_id && e.status === "active")}
            predecessor={byID(current.rotated_from)} successor={byID(current.rotated_to)} inUse={inUseAfter(current)}
            onFollow={follow}
            onRotated={async (id) => { await reload(); setDone(null); setRotatedTo(id); }}
            onDone={(text) => { setDone(text); setRotatedTo(null); void reload(); onChanged?.(); }} />
        )}
      </div>
    </>
  );
}

/** A pending key replaces the Mac's active key when approved, if it has one. */
function EnrollmentInspector({ enrollment: e, active, predecessor, successor, inUse, evidenceVersion, onClose, onDone, onRotated, onFollow }: {
  enrollment: Enrollment; active: Enrollment | undefined; predecessor: Enrollment | undefined; successor: Enrollment | undefined;
  /** For a rotated key, the active key its rotations led to, if the list has it. */
  inUse: Enrollment | undefined;
  evidenceVersion: number; onClose: () => void; onDone: (message: string) => void;
  /** The server refused a revoke because the key was rotated: its answer names the key in use. */
  onRotated: (keyInUse: string) => Promise<void>; onFollow: (deviceID: string) => void;
}) {
  const api = useApi();
  const newMac = !active;
  const replacesEnclaveKey = active?.key_storage === "secure_enclave";
  // A reinstall keeps the hardware UUID, so a different one is the first thing to read.
  const otherHardware = e.status === "pending" && active && e.hardware_uuid !== active.hardware_uuid ? active : undefined;
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canManage = useCan("admin");
  async function act(action: "approve" | "revoke") {
    setBusy(true);
    try {
      if (action === "approve") await api.approveEnrollment(e.device_id);
      else await api.revokeEnrollment(e.device_id);
      onDone(action === "approve"
        ? `Approved the new key for ${e.serial}. Its previous key no longer works.`
        : `Revoked the key for ${e.serial}. The Mac can’t report with it any more.`);
    } catch (err) {
      if (err instanceof ApiError && err.body.code === "credential_rotated" && err.body.current_device_id) {
        await onRotated(err.body.current_device_id);
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  }

  return (
    <aside className="inspector" aria-label="Enrollment details">
      <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
        <div style={{ flex: 1 }}>
          <h2 className="data" style={{ fontSize: 18, lineHeight: "24px" }}>{e.serial}</h2>
          <div className="badges"><Status enrollment={e} explain /></div>
        </div>
        <button type="button" className="button icon-button" aria-label="Close details" onClick={onClose}><CloseIcon /></button>
      </div>
      {otherHardware && (
        <p className="secondary" style={{ marginTop: 12 }}>
          <span className="tag attention"><AttentionGlyph /> Warning</span>{" "}
          {`The new key reports a different hardware UUID (${e.hardware_uuid}, was ${otherHardware.hardware_uuid}). Expect this only after a logic board replacement.`}
        </p>
      )}
      {e.status !== "revoked" && !canManage && <RoleNote>Approving and revoking enrollments needs the admin role.</RoleNote>}
      {e.status !== "revoked" && canManage && (
        <div className="actions">
          {e.status === "pending" && (
            <button type="button" className="button primary" disabled={busy} onClick={() => act("approve")}>Approve</button>
          )}
          <button type="button" className="button destructive" onClick={() => setConfirming(true)}>
            {e.status === "pending" ? "Reject…" : "Revoke…"}
          </button>
        </div>
      )}
      {error && <div style={{ margin: "8px -16px 0" }}><Banner>{error}</Banner></div>}
      <div className="group">
        <Details rows={[
          ["Key fingerprint", <span key="fp" className="data"><Fingerprint publicKey={e.public_key} /></span>],
          ["Device ID", <span key="id" className="data">{e.device_id}</span>],
          ...(e.rotated_from ? [["Rotated from", predecessor
            ? <KeyLink key="from" enrollment={predecessor} onFollow={onFollow} />
            : <Missing key="from">Not in this list</Missing>] as [string, JSX.Element]] : []),
          ["Key kept in", <Explain key="kept" tip={explanations.keyStorage} bare><KeyKeptIn storage={e.key_storage} /></Explain>],
          ["Hardware UUID", <span key="hw" className="data">{e.hardware_uuid}</span>],
          ["Enrolled with", <Explain key="token" tip={explanations.enrolledWith} bare>
            {e.token ? <span className="data">{e.token}</span> : <Missing>Not recorded</Missing>}
          </Explain>],
          ["Enrolled", dateTime(e.created_at)],
          ["Activated", e.activated_at ? dateTime(e.activated_at) : <Missing key="activated">Not yet</Missing>],
          // A rotated key's date is in the note below, as when rotation replaced it.
          ...(isRotated(e) ? [] : [["Revoked", e.revoked_at ? dateTime(e.revoked_at) : <Missing key="revoked">Not revoked</Missing>]] as [string, JSX.Element | string][]),
        ]} />
      </div>
      {isRotated(e) && (
        <p className="secondary" style={{ marginTop: 12 }}>
          Replaced by rotation on {e.revoked_at ? dateTime(e.revoked_at) : "an unknown date"}.
          {inUse
            ? <> The key in use is <KeyLink enrollment={inUse} onFollow={onFollow} />.</>
            : successor && <> The key that replaced it is <KeyLink enrollment={successor} onFollow={onFollow} />.</>}
        </p>
      )}
      {e.status === "pending" && !newMac && (
        <p className="secondary" style={{ marginTop: 12 }}>
          This Mac enrolled again with a new key.
          {otherHardware ? " " : " Approve it if you expect that, for example after a reinstall. "}
          Its previous key keeps working until you approve.
        </p>
      )}
      {e.status === "pending" && replacesEnclaveKey && e.key_storage !== "secure_enclave" && (
        <p className="secondary" style={{ marginTop: 12 }}>
          The key this Mac uses now is in the Secure Enclave, but this new one isn’t. Find out why before you
          approve it.
        </p>
      )}
      {e.status === "active" && e.key_storage !== "secure_enclave" && (
        <p className="secondary" style={{ marginTop: 12 }}>
          This key is in a file, so someone with admin rights on the Mac could copy it and report as this Mac from
          elsewhere. The agent moves this key into the Secure Enclave by itself, or, on a Mac without one,
          replaces it every 30 days.
        </p>
      )}
      {e.status === "pending" && newMac && (
        <p className="secondary" style={{ marginTop: 12 }}>
          This Mac is waiting for approval. Approve it to start recording it.
        </p>
      )}
      {e.status === "pending" && (
        <PendingCheckIn key={e.device_id} serial={e.serial} newMac={newMac} refreshVersion={evidenceVersion} />
      )}
      {confirming && (
        <ConfirmSheet
          title={e.status === "pending" ? `Reject the new key for ${e.serial}?` : `Revoke the key for ${e.serial}?`}
          message={e.status === "pending"
            ? active
              ? "The Mac keeps reporting with its previous key."
              : "This Mac has no active key, so it can’t report until it enrols again with a new key."
            : "The Mac can’t report with this key. Unless re-enrolment needs approval, it enrols again on its next check-in."}
          confirm={e.status === "pending" ? "Reject" : "Revoke"} destructive busy={busy}
          onConfirm={() => act("revoke")} onCancel={() => setConfirming(false)} />
      )}
    </aside>
  );
}

/** Fetch Fleet evidence only while a pending key is selected. */
function PendingCheckIn({ serial, newMac, refreshVersion }: { serial: string; newMac: boolean; refreshVersion: number }) {
  const api = useApi();
  const { data, error } = useLoad(() => api.devices(), [serial, refreshVersion], 30_000);
  if (!data || error) return null;
  const device = data.find((d) => d.serial === serial);
  return (
    <p className="secondary" style={{ marginTop: 12 }}>
      {device
        ? `This Mac last checked in ${relativeTime(lastCheckIn(device)).toLowerCase()}${newMac ? "" : " with its current key"}.`
        : "This Mac hasn’t checked in yet."}
    </p>
  );
}
