import { useSyncExternalStore } from "react";

/** The console's colour themes. Each sets the tokens in styles.css for light and dark;
 *  state colours keep their meaning in every theme. Mono, the brand's, is the default. */
export type Theme = "mono" | "slate" | "moss" | "paper";
export type Appearance = "system" | "light" | "dark";
export type Look = { theme: Theme; appearance: Appearance };

export const themes: { value: Theme; title: string }[] = [
  { value: "mono", title: "Mono" }, { value: "slate", title: "Slate" },
  { value: "moss", title: "Moss" }, { value: "paper", title: "Paper" },
];
export const appearances: { value: Appearance; title: string }[] = [
  { value: "system", title: "System" }, { value: "light", title: "Light" }, { value: "dark", title: "Dark" },
];

// Per browser, like the update check: a look is a preference, not a server setting.
const KEY = "altiward.look";
const DEFAULT: Look = { theme: "mono", appearance: "system" };

function read(): Look {
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) ?? "null") as Partial<Look> | null;
    return {
      theme: themes.some((t) => t.value === saved?.theme) ? saved!.theme! : DEFAULT.theme,
      appearance: appearances.some((a) => a.value === saved?.appearance) ? saved!.appearance! : DEFAULT.appearance,
    };
  } catch {
    return DEFAULT;
  }
}

let look = read();
const listeners = new Set<() => void>();

/** Sets data-theme and data-appearance on <html>, which styles.css reads. main.tsx calls it
 *  before the first render, so the page never paints in the wrong theme. */
export function applyLook(next: Look = look) {
  const root = document.documentElement;
  root.dataset.theme = next.theme;
  root.dataset.appearance = next.appearance;
}

export function setLook(change: Partial<Look>) {
  look = { ...look, ...change };
  try { localStorage.setItem(KEY, JSON.stringify(look)); } catch { /* this visit only */ }
  applyLook();
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function useLook(): Look {
  return useSyncExternalStore(subscribe, () => look);
}

const darkQuery = () => (typeof window.matchMedia === "function" ? window.matchMedia("(prefers-color-scheme: dark)") : null);

function subscribeSystem(listener: () => void) {
  const query = darkQuery();
  query?.addEventListener("change", listener);
  return () => query?.removeEventListener("change", listener);
}

/** Whether the console is showing dark now: the chosen appearance, or the system's. */
export function useDark(): boolean {
  const { appearance } = useLook();
  const systemDark = useSyncExternalStore(subscribeSystem, () => darkQuery()?.matches ?? false);
  return appearance === "system" ? systemDark : appearance === "dark";
}
