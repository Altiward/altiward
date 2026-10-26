import { type JSX, useMemo, useState } from "react";
import type { CredentialStatus, Enrollment, KeyStorage } from "../api";
import { Banner, Details, Empty, Explain, Missing, RoleNote, SearchField, Segmented, Toolbar } from "../components/Chrome";
import { Fingerprint } from "../components/Fingerprint";
import { AttentionGlyph, ChipGlyph, CloseIcon, EndedGlyph, FileGlyph } from "../components/Icons";
import { ConfirmSheet } from "../components/Sheet";
import { StateBadge } from "../components/StateBadge";
import { Table } from "../components/Table";
import { useApi, useCan } from "../context";
import { explanations } from "../explanations";
import { dateTime, lastCheckIn, relativeTime } from "../format";
import { useLoad } from "../useLoad";

type Filter = CredentialStatus | "all";
const statusTitle: Record<CredentialStatus, string> = { active: "Active", pending: "Waiting for approval", revoked: "Revoked" };
const statusLook = { active: "verified", pending: "claimed", revoked: "ended" } as const;
const Status = ({ status }: { status: CredentialStatus }) => <StateBadge state={statusLook[status]} label={statusTitle[status]} />;

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

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data ?? []).filter((e) => (filter === "all" || e.status === filter) && (!q || e.serial.toLowerCase().includes(q)));
  }, [data, filter, query]);
  const current = rows.find((e) => e.device_id === selected) ?? null;
  const pending = (data ?? []).filter((e) => e.status === "pending").length;

  return (
    <>
      <Toolbar title="Enrollments" subtitle={pending ? `${pending} waiting for approval` : undefined} onRefresh={() => { void reload(); setEvidenceVersion((v) => v + 1); }}>
        <Segmented label="Show" value={filter} onChange={setFilter} options={[
          { value: "all", title: "All" }, { value: "pending", title: "Waiting" },
          { value: "active", title: "Active" }, { value: "revoked", title: "Revoked" },
        ]} />
        <SearchField value={query} onChange={setQuery} placeholder="Search serial numbers" />
      </Toolbar>
      <div className={`split${current ? " with-inspector" : ""}`}>
        <div className="pane">
          {error && <Banner>{error}</Banner>}
          {done && <Banner kind="info">{done}</Banner>}
          {data && rows.length === 0 ? (
            <Empty title={data.length ? "No matching enrollments" : "No Macs enrolled yet"}>
              {data.length ? "Try another filter." : "A Mac enrolls the first time its agent reaches the server with your enrollment token."}
            </Empty>
          ) : (
            <Table label="Enrollments" rows={rows} rowKey={(e) => e.device_id} selected={selected} onSelect={setSelected}
              initialSort={{ key: "enrolled", descending: true }}
              columns={[
                { key: "mac", title: "Mac", sort: (e) => e.serial, render: (e) => <span className="data">{e.serial}</span> },
                { key: "status", title: "Status", sort: (e) => e.status, render: (e) => <Status status={e.status} /> },
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
            onDone={(text) => { setDone(text); void reload(); onChanged?.(); }} />
        )}
      </div>
    </>
  );
}

/** A pending key replaces the Mac's active key when approved, if it has one. */
function EnrollmentInspector({ enrollment: e, active, evidenceVersion, onClose, onDone }: {
  enrollment: Enrollment; active: Enrollment | undefined; evidenceVersion: number; onClose: () => void;
  onDone: (message: string) => void;
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
      setError(err instanceof Error ? err.message : String(err));
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
          <div className="badges"><Status status={e.status} /></div>
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
          ["Key kept in", <Explain key="kept" tip={explanations.keyStorage} bare><KeyKeptIn storage={e.key_storage} /></Explain>],
          ["Hardware UUID", <span key="hw" className="data">{e.hardware_uuid}</span>],
          ["Enrolled", dateTime(e.created_at)],
          ["Activated", e.activated_at ? dateTime(e.activated_at) : <Missing key="activated">Not yet</Missing>],
          ["Revoked", e.revoked_at ? dateTime(e.revoked_at) : <Missing key="revoked">Not revoked</Missing>],
        ]} />
      </div>
      {e.status === "pending" && !newMac && (
        <p className="secondary" style={{ marginTop: 12 }}>
          This Mac enrolled again with a new key.
          {otherHardware ? " " : " Approve it if you expect that, for example after a reinstall. "}
          Its previous key keeps working until you approve.
        </p>
      )}
      {e.status === "pending" && replacesEnclaveKey && e.key_storage !== "secure_enclave" && (
        <p className="secondary" style={{ marginTop: 12 }}>
          The key this Mac uses now is in the Secure Enclave, but this new one isn’t. An agent older than 0.2.0
          installed over a newer one does that; otherwise, find out why before you approve it.
        </p>
      )}
      {e.status === "active" && e.key_storage !== "secure_enclave" && (
        <p className="secondary" style={{ marginTop: 12 }}>
          This key is in a file, so someone with admin rights on the Mac could copy it and report as this Mac from
          elsewhere. Revoke it to make the Mac enroll again: with agent 0.2.0 or later on a Mac with a Secure
          Enclave, the new key is kept there.
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
            ? "The Mac keeps reporting with its previous key."
            : "The Mac can’t report with this key. Unless re-enrollment needs approval, it enrolls again on its next check-in."}
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
