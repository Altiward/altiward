import { formatDuration, gauge } from "../format";

/** Time used against time allowed, with a mark at the allowance. Orange (elevated-ink)
 *  while admin is held, muted once ended, crimson past expiry. */
export function Gauge({ actual, allowed, ended }: { actual: number | null; allowed: number | null; ended?: boolean }) {
  if (actual == null) return <span className="secondary">—</span>;
  const g = gauge(actual, allowed);
  const text = allowed == null ? formatDuration(actual) : `${formatDuration(actual)} of ${formatDuration(allowed)}`;
  const label = allowed == null ? `${text}, no expiry known` : `${text}${g.overrun ? ", past expiry" : ""}`;
  return (
    <span className={`gauge${g.overrun ? " over" : ""}${ended ? " ended" : ""}`} role="img" aria-label={label}>
      {g.fill != null && (
        <span className="track">
          <span className="fill" style={{ width: `${g.fill * 100}%` }} />
          <span className="ceiling" style={{ left: `${g.ceiling! * 100}%` }} />
        </span>
      )}
      <span className="data gauge-text">{text}</span>
    </span>
  );
}
