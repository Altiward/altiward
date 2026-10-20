import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";

// No test reaches the network: a test that needs fetch stubs its own.
beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("no network in tests"); }));
});

afterEach(() => {
  vi.unstubAllGlobals();
  try { localStorage.clear(); } catch { /* none */ }
});
