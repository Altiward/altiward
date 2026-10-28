// Glyphs per the brand book: 14px on a 14 grid, 2px stroke, square caps, one colour
// taken from the text beside them. Filled shapes only for the Elevated step. No shields,
// padlocks or keys.
const base = {
  width: 14, height: 14, viewBox: "0 0 14 14", fill: "none", stroke: "currentColor", strokeWidth: 2,
  strokeLinecap: "square" as const, strokeLinejoin: "miter" as const, "aria-hidden": true,
};

/** The Elevated step: admin held now. */
export const ElevatedGlyph = () => (
  <svg {...base} stroke="none" fill="currentColor"><path d="M1 12h12V8H9V4H5v4H1z" /></svg>
);
export const VerifiedGlyph = () => <svg {...base}><path d="M2 7.5l3.5 3.5L12 3.5" /></svg>;
export const ClaimedGlyph = () => <svg {...base}><path d="M5 5a2 2 0 114 0c0 1.5-2 1.5-2 3M7 11.5v.5" /></svg>;
export const NotGrantedGlyph = () => <svg {...base}><path d="M2 2l10 10M12 2L2 12" /></svg>;
export const EndedGlyph = () => <svg {...base}><path d="M2 11h10" /></svg>;
/** A key replaced by rotation: an arrow handing on to a new mark. */
export const RotatedGlyph = () => <svg {...base}><path d="M2 5h9M8 2l3 3-3 3M2 11h10" /></svg>;
/** A key kept in the Secure Enclave: a chip. */
export const ChipGlyph = () => <svg {...base}><path d="M4 4h6v6H4zM1 6h3M1 8.5h3M10 6h3M10 8.5h3" /></svg>;
/** A key kept in a file: a page. */
export const FileGlyph = () => <svg {...base}><path d="M3 1h5l3 3v9H3zM8 1v3h3" /></svg>;
/** A newer release is out. */
export const UpdateGlyph = () => <svg {...base}><path d="M7 12V3M3 6l4-4 4 4" /></svg>;
/** Needs attention soon, such as a release that fixes a security problem. */
export const AttentionGlyph = () => <svg {...base}><path d="M7 2v6M7 11v1" /></svg>;

/** A section that folds away: points right while closed, down while open (styles.css). */
export const DisclosureGlyph = () => <svg {...base}><path d="M5 3l4 4-4 4" /></svg>;

export const OverviewIcon = () => <svg {...base}><path d="M2 2h4v4H2zM8 2h4v4H8zM2 8h4v4H2zM8 8h4v4H8z" /></svg>;
export const SessionsIcon = () => <svg {...base}><path d="M2 3h10M2 7h10M2 11h6" /></svg>;
export const FleetIcon = () => <svg {...base}><path d="M2 3h10v6H2zM0 12h14" /></svg>;
export const EnrollIcon = () => <svg {...base}><path d="M2 2h10v10H2zM5 7h4M7 5v4" /></svg>;
export const CommandsIcon = () => <svg {...base}><path d="M2 7h8M7 4l3 3-3 3M12 2v10" /></svg>;
export const ActivityIcon = () => <svg {...base}><path d="M2 2v10h10M5 9l2-3 2 2 3-4" /></svg>;
export const SettingsIcon = () => <svg {...base}><path d="M1 4h12M1 10h12M4 2v4M10 8v4" /></svg>;
export const RefreshIcon = () => <svg {...base}><path d="M12 7a5 5 0 11-1.5-3.5M12 1v3H9" /></svg>;
export const SearchIcon = () => <svg {...base}><path d="M6 10a4 4 0 100-8 4 4 0 000 8zM9 9l4 4" /></svg>;
export const CloseIcon = () => <svg {...base}><path d="M3 3l8 8M11 3l-8 8" /></svg>;
