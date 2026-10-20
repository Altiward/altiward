import { useState } from "react";
import type { Command } from "../api";
import { Banner, Empty, Segmented, Toolbar } from "../components/Chrome";
import { StateBadge } from "../components/StateBadge";
import { Table } from "../components/Table";
import { useApi } from "../context";
import { commandOutcome as outcome, dateTime } from "../format";
import { useLoad } from "../useLoad";

type Filter = "all" | Command["status"];
const statusTitle: Record<Command["status"], string> = {
  pending: "Waiting for Mac", completed: "Done", failed: "Failed", skipped: "Nothing to do", expired: "Expired",
};
const statusLook = { pending: "claimed", completed: "verified", failed: "not-granted", skipped: "ended", expired: "ended" } as const;

/** Remote commands and what each Mac did with them. */
export function CommandsView() {
  const api = useApi();
  const [filter, setFilter] = useState<Filter>("all");
  const { data, error, reload } = useLoad(() => api.commands(filter === "all" ? {} : { status: filter }), [filter], 15_000);

  return (
    <>
      <Toolbar title="Commands" onRefresh={reload}>
        <Segmented label="Show" value={filter} onChange={setFilter} options={[
          { value: "all", title: "All" }, { value: "pending", title: "Waiting" },
          { value: "completed", title: "Done" }, { value: "failed", title: "Failed" },
        ]} />
      </Toolbar>
      <div className="split">
        <div className="pane">
          {error && <Banner>{error}</Banner>}
          {data && data.length === 0 ? (
            <Empty title="No commands yet">Revokes you send from Admins now, Sessions or Fleet appear here.</Empty>
          ) : (
            <Table label="Commands" rows={data ?? []} rowKey={(c) => c.command_id} initialSort={{ key: "issued", descending: true }}
              columns={[
                { key: "issued", title: "Issued", sort: (c) => new Date(c.created_at).getTime(),
                  render: (c) => <span className="secondary small">{dateTime(c.created_at)}</span> },
                { key: "mac", title: "Mac", sort: (c) => c.serial, render: (c) => <span className="data">{c.serial}</span> },
                { key: "target", title: "Revoke", sort: (c) => c.user ?? "", render: (c) => c.user ?? "All admins" },
                { key: "status", title: "Status", sort: (c) => c.status,
                  render: (c) => <StateBadge state={statusLook[c.status]} label={statusTitle[c.status]} /> },
                { key: "outcome", title: "Outcome", render: (c) => <span title={outcome(c)}>{outcome(c)}</span> },
              ]} />
          )}
        </div>
      </div>
    </>
  );
}
