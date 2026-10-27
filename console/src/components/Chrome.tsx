import { type ReactNode, useId, useLayoutEffect, useRef, useState } from "react";
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

type Box = { left: number; right: number; top: number; bottom: number };

/** Where a help tag of `size` goes for a term at `term`, in a window of `view`: below the
 *  term, from its left edge (its right edge for `end`), moved to stay `margin` inside the
 *  window, and above the term when there's no room below. */
export function tipPosition(term: Box, size: { width: number; height: number }, align: "start" | "end",
  view: { width: number; height: number }, gap = 6, margin = 8): { left: number; top: number } {
  const wanted = align === "end" ? term.right - size.width : term.left;
  const left = Math.max(margin, Math.min(wanted, view.width - margin - size.width));
  const below = term.bottom + gap;
  const above = term.top - gap - size.height;
  const top = below + size.height > view.height - margin && above >= margin ? above : below;
  return { left, top };
}

/** A term with a short explanation, shown on hover and on keyboard focus like a macOS help
 *  tag. Escape hides it. The tag is placed on the window, not in the term's pane, so a pane
 *  never cuts it off or scrolls sideways for it. `align="end"` lines it up with the term's
 *  right edge, for terms near the right of the page; `bare` drops the dotted underline, for
 *  badges and tags. */
export function Explain({ tip, children, align = "start", bare }: {
  tip: string; children: ReactNode; align?: "start" | "end"; bare?: boolean;
}) {
  const id = useId();
  const term = useRef<HTMLSpanElement>(null);
  const tag = useRef<HTMLSpanElement>(null);
  const [hidden, setHidden] = useState(false);
  const [open, setOpen] = useState(false);
  const [at, setAt] = useState<{ left: number; top: number }>();
  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      if (!term.current || !tag.current) return;
      setAt(tipPosition(term.current.getBoundingClientRect(), tag.current.getBoundingClientRect(), align,
        { width: window.innerWidth, height: window.innerHeight }));
    };
    place();
    // A pane scrolled under the pointer moves the term, and the tag goes with it.
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);
    return () => {
      window.removeEventListener("scroll", place, true);
      window.removeEventListener("resize", place);
    };
  }, [open, align]);
  const close = () => { setOpen(false); setHidden(false); };
  return (
    <span ref={term} className={`explain${bare ? " bare" : ""}${hidden ? " dismissed" : ""}`} tabIndex={0}
      aria-describedby={id} onKeyDown={(e) => { if (e.key === "Escape") setHidden(true); }}
      onMouseEnter={() => setOpen(true)} onFocus={() => setOpen(true)} onBlur={close} onMouseLeave={close}>
      {children}
      <span ref={tag} role="tooltip" id={id} className="explain-tip" style={at}>{tip}</span>
    </span>
  );
}
