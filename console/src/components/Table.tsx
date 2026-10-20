import { type KeyboardEvent, type ReactNode, useMemo, useState } from "react";

export interface Column<T> {
  key: string;
  title: string;
  render: (row: T) => ReactNode;
  /** Value to sort by; omit to make the column unsortable. */
  sort?: (row: T) => string | number;
  align?: "right";
}

interface Props<T> {
  label: string;
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  selected?: string | null;
  onSelect?: (key: string | null) => void;
  initialSort?: { key: string; descending?: boolean };
}

/** Sortable, selectable table in the macOS bordered style. Click a heading to sort;
 *  click it again to reverse. Up and Down move the selection; Escape clears it. */
export function Table<T>({ label, rows, columns, rowKey, selected, onSelect, initialSort }: Props<T>) {
  const [sort, setSort] = useState(initialSort ?? null);
  const sorted = useMemo(() => {
    const col = columns.find((c) => c.key === sort?.key);
    if (!col?.sort) return rows;
    const by = col.sort;
    const out = [...rows].sort((a, b) => {
      const x = by(a), y = by(b);
      return x < y ? -1 : x > y ? 1 : 0;
    });
    return sort!.descending ? out.reverse() : out;
  }, [rows, columns, sort]);

  function onKeyDown(e: KeyboardEvent) {
    if (!onSelect || sorted.length === 0) return;
    const i = sorted.findIndex((r) => rowKey(r) === selected);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next = e.key === "ArrowDown" ? Math.min(sorted.length - 1, i + 1) : Math.max(0, i - 1);
      onSelect(rowKey(sorted[next]));
    } else if (e.key === "Escape") {
      onSelect(null);
    }
  }

  return (
    <table className="list" aria-label={label} tabIndex={0} onKeyDown={onKeyDown} role="grid">
      <thead>
        <tr>
          {columns.map((c) => {
            const active = sort?.key === c.key;
            return (
              <th key={c.key} className={c.align === "right" ? "num" : undefined}
                aria-sort={active ? (sort!.descending ? "descending" : "ascending") : undefined}>
                {c.sort ? (
                  <button type="button" onClick={() => setSort({ key: c.key, descending: active ? !sort!.descending : false })}>
                    {c.title}
                    {active && <span aria-hidden>{sort!.descending ? "▾" : "▴"}</span>}
                  </button>
                ) : (
                  <button type="button" disabled tabIndex={-1}>{c.title}</button>
                )}
              </th>
            );
          })}
        </tr>
      </thead>
      <tbody>
        {sorted.map((row) => {
          const key = rowKey(row);
          return (
            <tr key={key} aria-selected={key === selected} onClick={() => onSelect?.(key === selected ? null : key)}>
              {columns.map((c) => (
                <td key={c.key} className={c.align === "right" ? "num" : undefined}>{c.render(row)}</td>
              ))}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
