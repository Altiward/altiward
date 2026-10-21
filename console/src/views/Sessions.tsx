import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { Banner, Empty, SearchField, Segmented, Toolbar } from "../components/Chrome";
import {
  flagsColumn, macColumn, startedColumn, stateColumn, usedColumn, userColumn,
} from "../components/SessionColumns";
import { SessionInspector } from "../components/SessionInspector";
import { Table } from "../components/Table";
import { useApi } from "../context";
import { useLoad } from "../useLoad";

type Filter = "all" | "elevated" | "ended";

/** Every elevation session, newest first. */
export function SessionsView() {
  const api = useApi();
  const { data, error, reload } = useLoad(() => api.sessions({ limit: 500 }), [], 30_000);
  const [filter, setFilter] = useState<Filter>("all");
  const [params] = useSearchParams();
  const [query, setQuery] = useState(params.get("q") ?? "");
  const [selected, setSelected] = useState<string | null>(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data ?? []).filter((s) =>
      (filter === "all" || (filter === "elevated") === s.open) &&
      (!q || [s.local_user, s.upn ?? "", s.device_serial, s.reason ?? ""].some((v) => v.toLowerCase().includes(q))),
    );
  }, [data, filter, query]);
  const current = rows.find((s) => s.session_id === selected) ?? null;

  return (
    <>
      <Toolbar title="Sessions" subtitle={data ? `${rows.length} of ${data.length}` : undefined} onRefresh={reload}>
        <Segmented label="Show" value={filter} onChange={setFilter}
          options={[{ value: "all", title: "All" }, { value: "elevated", title: "Elevated" }, { value: "ended", title: "Ended" }]} />
        <SearchField value={query} onChange={setQuery} placeholder="Search users, Macs, reasons" />
      </Toolbar>
      <div className={`split${current ? " with-inspector" : ""}`}>
        <div className="pane">
          {error && <Banner>{error}</Banner>}
          {data && rows.length === 0 ? (
            <Empty title={data.length ? "No matching sessions" : "No sessions yet"}>
              {data.length ? "Try another search or filter." : "Sessions appear here when someone gets admin rights on an enrolled Mac."}
            </Empty>
          ) : (
            <Table label="Sessions" rows={rows} rowKey={(s) => s.session_id} selected={selected} onSelect={setSelected}
              columns={[stateColumn, userColumn, macColumn, startedColumn, usedColumn, flagsColumn]}
              initialSort={{ key: "started", descending: true }} />
          )}
        </div>
        {current && <SessionInspector session={current} onClose={() => setSelected(null)} onChanged={reload} />}
      </div>
    </>
  );
}
