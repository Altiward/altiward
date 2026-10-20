import { useEffect, useRef } from "react";

interface Props {
  title: string;
  message: string;
  confirm: string;
  destructive?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/** A confirmation sheet for consequential actions. Cancel has keyboard focus, so
 *  Return never confirms a destructive action by accident. */
export function ConfirmSheet({ title, message, confirm, destructive, busy, onConfirm, onCancel }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) {
      if (d.showModal) d.showModal();
      else d.setAttribute("open", ""); // test DOMs without dialog support
    }
    cancel.current?.focus();
  }, []);
  return (
    <dialog ref={ref} className="sheet" aria-labelledby="sheet-title" onCancel={(e) => { e.preventDefault(); onCancel(); }}>
      <h2 id="sheet-title">{title}</h2>
      <p>{message}</p>
      <div className="buttons">
        <button type="button" className="button" ref={cancel} onClick={onCancel}>Cancel</button>
        <button type="button" className={`button primary${destructive ? " destructive" : ""}`} disabled={busy} onClick={onConfirm}>
          {confirm}
        </button>
      </div>
    </dialog>
  );
}
