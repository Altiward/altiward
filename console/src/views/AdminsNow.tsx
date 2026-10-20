import { useMemo, useState } from "react";
import { Banner, Empty, SearchField, Toolbar } from "../components/Chrome";
import { flagsColumn, macColumn, startedColumn, stateColumn, usedColumn, userColumn } from "../components/SessionColumns";
import { SessionInspector } from "../components/SessionInspector";
import { Table } from "../components/Table";
import { useApi } from "../context";
import { useLoad } from "../useLoad";

/** Everyone who holds admin rights right now. Overruns and rights without a grant first. */
export function AdminsNowView() {
  const api = useApi();
  const { data, error, reload } = useLoad(() => api.sessions({ open: true }), [], 15_000);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const urgency = (s: { source: string; overran: boolean }) => (s.source === "out_of_band" ? 2 : s.overran ? 1 : 0);
    return (data ?? [])
      .filter((s) => !q || [s.local_user, s.upn ?? "", s.device_serial].some((v) => v.toLowerCase().includes(q)))
      .sort((a, b) => urgency(b) - urgency(a) || (b.actual_seconds ?? 0) - (a.actual_seconds ?? 0));
  }, [data, query]);
  const current = rows.find((s) => s.session_id === selected) ?? null;
  const macs = new Set(rows.map((s) => s.device_serial)).size;

  return (
    <>
      <Toolbar title="Admins now"
        subtitle={data ? `${rows.length} ${rows.length === 1 ? "person" : "people"} on ${macs} ${macs === 1 ? "Mac" : "Macs"}` : undefined}
        onRefresh={reload}>
        <SearchField value={query} onChange={setQuery} placeholder="Search users or Macs" />
      </Toolbar>
      <div className={`split${current ? " with-inspector" : ""}`}>
        <div className="pane">
          {error && <Banner>{error}</Banner>}
          {data && rows.length === 0 ? (
            <Empty title={data.length ? "No matches" : "No one has admin rights right now"}>
              {data.length ? "Try another search." : "Permanent admins aren’t listed here. Fleet shows each Mac’s admin group."}
            </Empty>
          ) : (
            <Table label="People with admin rights" rows={rows} rowKey={(s) => s.session_id}
              selected={selected} onSelect={setSelected}
              columns={[stateColumn, userColumn, macColumn, usedColumn, startedColumn, flagsColumn]} />
          )}
        </div>
        {current && <SessionInspector session={current} onClose={() => setSelected(null)} onChanged={reload} />}
      </div>
    </>
  );
}
