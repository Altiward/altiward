import type { Session } from "../api";
import { flagTips } from "../explanations";
import { dateTime, flagLabel, sessionState } from "../format";
import { Gauge } from "./Gauge";
import { displayName } from "./SessionInspector";
import { StateBadge } from "./StateBadge";
import type { Column } from "./Table";

const time = (iso: string | null) => (iso ? new Date(iso).getTime() : 0);

export const userColumn: Column<Session> = {
  key: "user", title: "User", sort: (s) => displayName(s).toLowerCase(),
  render: (s) => <span title={s.local_user}>{displayName(s)}</span>,
};
export const macColumn: Column<Session> = {
  key: "mac", title: "Mac", sort: (s) => s.device_serial, render: (s) => <span className="data">{s.device_serial}</span>,
};
export const startedColumn: Column<Session> = {
  key: "started", title: "Started", sort: (s) => time(s.started_at),
  render: (s) => <span className="secondary small">{dateTime(s.started_at)}</span>,
};
export const usedColumn: Column<Session> = {
  key: "used", title: "Time used", sort: (s) => s.actual_seconds ?? 0,
  render: (s) => <Gauge actual={s.actual_seconds} allowed={s.allowed_seconds} ended={!s.open} />,
};
export const stateColumn: Column<Session> = {
  key: "state", title: "State", sort: (s) => sessionState(s), render: (s) => <StateBadge state={sessionState(s)} />,
};
export const flagsColumn: Column<Session> = {
  key: "flags", title: "Attention",
  render: (s) =>
    s.flags
      .filter((f) => f !== "out_of_band" && flagLabel(f) != null) // the Without a grant badge already says it
      .map((f) => <span key={f} className="tag attention" title={flagTips[f]}>{flagLabel(f)}</span>),
};
