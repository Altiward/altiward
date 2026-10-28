import { AttentionGlyph } from "./Icons";

/** Intune has synced and has no Mac with this serial. A word and a glyph, as every state. */
export function NotInIntune() {
  return (
    <span className="tag attention" title="Intune manages no Mac with this serial number">
      <AttentionGlyph /> Not in Intune
    </span>
  );
}
