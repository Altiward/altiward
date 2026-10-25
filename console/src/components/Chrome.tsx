import { type ReactNode, useId, useState } from "react";
import { RefreshIcon, SearchIcon } from "./Icons";

export function Toolbar({ title, subtitle, children, onRefresh }: {
  title: string; subtitle?: string; children?: ReactNode; onRefresh?: () => void;
}) {
  return (
    <header className="toolbar">
      <div>
        <h1>{title}</h1>
        {subtitle && <div className="subtitle">{subtitle}</div>}
      </div>
      <div className="spacer" />
      {children}
      {onRefresh && (
        <button type="button" className="button icon-button" onClick={onRefresh} aria-label="Refresh" title="Refresh">
          <RefreshIcon />
        </button>
      )}
    </header>
  );
}

export function SearchField({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <label className="search">
      <SearchIcon />
      <input type="search" value={value} placeholder={placeholder} aria-label={placeholder}
        onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}

export function Segmented<T extends string>({ label, options, value, onChange }: {
  label: string; options: { value: T; title: string }[]; value: T; onChange: (v: T) => void;
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>{o.title}</button>
      ))}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><strong>{title}</strong>{children && <span>{children}</span>}</div>;
}

/** A value that's missing, as a word that says why ("Not set", "Not reported") in secondary
 *  text, so a screen reader reads it and the reader knows what to do about it. */
export function Missing({ children }: { children: string }) {
  return <span className="secondary">{children}</span>;
}

export function Banner({ children, kind = "error" }: { children: ReactNode; kind?: "error" | "info" }) {
  return <div className={`banner${kind === "info" ? " info" : ""}`} role={kind === "error" ? "alert" : "status"}>{children}</div>;
}

export function Details({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <div className="box">
      <dl>{rows.map(([k, v]) => [<dt key={`${k}-t`}>{k}</dt>, <dd key={`${k}-d`}>{v}</dd>])}</dl>
    </div>
  );
}

/** Says why an action is missing: the person's role doesn't include it. */
export function RoleNote({ children }: { children: ReactNode }) {
  return <p className="role-note">{children} Ask an Altiward admin if you need to.</p>;
}

/** A term with a short explanation, shown on hover and on keyboard focus like a macOS help
 *  tag. Escape hides it. `align="end"` anchors it to the term's right edge, for terms near
 *  the right of the page; `bare` drops the dotted underline, for badges and tags. */
export function Explain({ tip, children, align = "start", bare }: {
  tip: string; children: ReactNode; align?: "start" | "end"; bare?: boolean;
}) {
  const id = useId();
  const [hidden, setHidden] = useState(false);
  return (
    <span className={`explain${align === "end" ? " end" : ""}${bare ? " bare" : ""}${hidden ? " dismissed" : ""}`} tabIndex={0}
      aria-describedby={id} onKeyDown={(e) => { if (e.key === "Escape") setHidden(true); }}
      onBlur={() => setHidden(false)} onMouseLeave={() => setHidden(false)}>
      {children}
      <span role="tooltip" id={id} className="explain-tip">{tip}</span>
    </span>
  );
}
