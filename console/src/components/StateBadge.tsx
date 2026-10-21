import type { JSX } from "react";
import { stateTips } from "../explanations";
import type { State } from "../format";
import { Explain } from "./Chrome";
import { ClaimedGlyph, ElevatedGlyph, EndedGlyph, NotGrantedGlyph, VerifiedGlyph } from "./Icons";

const words: Record<State, string> = {
  elevated: "Elevated", verified: "Verified", claimed: "Claimed", "not-granted": "Without a grant", ended: "Ended",
};
const glyphs: Record<State, () => JSX.Element> = {
  elevated: ElevatedGlyph, verified: VerifiedGlyph, claimed: ClaimedGlyph, "not-granted": NotGrantedGlyph, ended: EndedGlyph,
};

/** The brand's StateBadge: a word and a glyph, never colour alone. `label` replaces the
 *  word when the badge describes something other than an admin session (an enrollment,
 *  a command) but borrows the same look. A session state explains itself: a hover hint
 *  by default, or with `explain` a help tag that keyboards reach too, for the inspector. */
export function StateBadge({ state, label, explain }: { state: State; label?: string; explain?: boolean }) {
  const Glyph = glyphs[state];
  const tip = label ? undefined : stateTips[state];
  const badge = <span className={`badge ${state}`} title={explain ? undefined : tip}><Glyph />{label ?? words[state]}</span>;
  return explain && tip ? <Explain tip={tip} bare>{badge}</Explain> : badge;
}
