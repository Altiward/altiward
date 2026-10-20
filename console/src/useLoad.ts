import { useCallback, useEffect, useRef, useState } from "react";

/** Loads data, keeps the last good result while reloading, and optionally refreshes on
 *  an interval while the page is visible. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[], refreshMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const latest = useRef(load);
  latest.current = load;

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await latest.current());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    if (!refreshMs) return;
    const t = setInterval(() => { if (document.visibilityState === "visible") void reload(); }, refreshMs);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload };
}
