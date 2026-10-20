import { useMemo, useState } from "react";
import type { CredentialStatus, Enrollment } from "../api";
import { Banner, Details, Empty, RoleNote, SearchField, Segmented, Toolbar } from "../components/Chrome";
import { Fingerprint } from "../components/Fingerprint";
import { CloseIcon } from "../components/Icons";
import { ConfirmSheet } from "../components/Sheet";
import { StateBadge } from "../components/StateBadge";
import { Table } from "../components/Table";
import { useApi, useCan } from "../context";
import { dateTime } from "../format";
import { useLoad } from "../useLoad";

type Filter = CredentialStatus | "all";
const statusTitle: Record<CredentialStatus, string> = { active: "Active", pending: "Waiting for approval", revoked: "Revoked" };
const statusLook = { active: "verified", pending: "claimed", revoked: "ended" } as const;
const Status = ({ status }: { status: CredentialStatus }) => <StateBadge state={statusLook[status]} label={statusTitle[status]} />;

/** Device credentials: approve re-enrollments, revoke lost Macs. */
export function EnrollmentsView({ onChanged }: { onChanged?: () => void }) {
  const api = useApi();
  const { data, error, reload } = useLoad(() => api.enrollments(), [], 30_000);
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
      <Toolbar title="Enrollments" subtitle={pending ? `${pending} waiting for approval` : undefined} onRefresh={reload}>
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
                { key: "key", title: "Key", render: (e) => <span className="data secondary"><Fingerprint publicKey={e.public_key} /></span> },
                { key: "enrolled", title: "Enrolled", sort: (e) => new Date(e.created_at).getTime(),
                  render: (e) => <span className="secondary small">{dateTime(e.created_at)}</span> },
              ]} />
          )}
        </div>
        {current && (
          <EnrollmentInspector enrollment={current} onClose={() => setSelected(null)}
            newMac={!(data ?? []).some((e) => e.serial === current.serial && e.device_id !== current.device_id && e.status === "active")}
            onDone={(text) => { setDone(text); void reload(); onChanged?.(); }} />
        )}
      </div>
    </>
  );
}

/** A Mac's credentials: a pending one for a Mac with no active one is a new Mac; a
 *  re-enrollment replaces the Mac's active key when approved. */
function EnrollmentInspector({ enrollment: e, newMac, onClose, onDone }: {
  enrollment: Enrollment; newMac: boolean; onClose: () => void; onDone: (message: string) => void;
}) {
  const api = useApi();
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
          ["Hardware UUID", <span key="hw" className="data">{e.hardware_uuid}</span>],
          ["Enrolled", dateTime(e.created_at)],
          ["Activated", dateTime(e.activated_at)],
          ["Revoked", dateTime(e.revoked_at)],
        ]} />
      </div>
      {e.status === "pending" && !newMac && (
        <p className="secondary" style={{ marginTop: 12 }}>
          This Mac enrolled again with a new key. Approve it if you expect that, for example after a
          reinstall. Its previous key keeps working until you approve.
        </p>
      )}
      {e.status === "pending" && newMac && (
        <p className="secondary" style={{ marginTop: 12 }}>
          This Mac is waiting for approval. Approve it to start recording it.
        </p>
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
