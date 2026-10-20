import { useEffect, useState } from "react";
import { useApi, useCan } from "./context";
import { type Check, checkReleases } from "./updates";

export type UpdateCheck =
  | { state: "off" }
  | { state: "checking"; running: string }
  | { state: "done"; running: string; check: Check };

/** The update check for an admin; null for other roles, who can't act on it, and while
 *  the server's version is loading. Nothing is fetched for them, or while the server
 *  turned the check off. */
export function useUpdateCheck(): UpdateCheck | null {
  const api = useApi();
  const admin = useCan("admin");
  const [result, setResult] = useState<UpdateCheck | null>(null);
  useEffect(() => {
    if (!admin) return;
    let live = true;
    (async () => {
      let about;
      try {
        about = await api.about();
      } catch {
        return;
      }
      if (about.update_check !== true) {
        if (live) setResult({ state: "off" });
        return;
      }
      if (live) setResult({ state: "checking", running: about.version });
      const check = await checkReleases();
      if (live) setResult({ state: "done", running: about.version, check });
    })();
    return () => { live = false; };
  }, [api, admin]);
  return admin ? result : null;
}
