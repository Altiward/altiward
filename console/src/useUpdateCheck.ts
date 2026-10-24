import { useCallback, useEffect, useState } from "react";
import { useApi, useCan } from "./context";
import { type Check, checkReleases } from "./updates";

/** Where the server runs, which decides how to upgrade it: azureApp is the container app's
 *  name on Azure Container Apps, and missing for the Compose bundle and the like. */
export interface Deployment { azureApp?: string }

export type UpdateCheck = Deployment & (
  | { state: "off" }
  | { state: "checking"; running: string }
  | { state: "done"; running: string; check: Check });

/** The update check for an admin; null for other roles, who can't act on it, and while
 *  the server's version is loading. Nothing is fetched for them, or while the server
 *  turned the check off. checkNow asks GitHub again (Settings' Check now). */
export function useUpdateCheck(): (UpdateCheck & { checkNow: () => void }) | null {
  const api = useApi();
  const admin = useCan("admin");
  const [result, setResult] = useState<UpdateCheck | null>(null);
  const [presses, setPresses] = useState(0);
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
      const where: Deployment = about.platform === "azure-container-apps" ? { azureApp: about.app } : {};
      if (about.update_check !== true) {
        if (live) setResult({ ...where, state: "off" });
        return;
      }
      if (live) setResult({ ...where, state: "checking", running: about.version });
      const check = await checkReleases(Date.now(), { running: about.version, force: presses > 0 });
      if (live) setResult({ ...where, state: "done", running: about.version, check });
    })();
    return () => { live = false; };
  }, [api, admin, presses]);
  const checkNow = useCallback(() => setPresses((n) => n + 1), []);
  return admin && result ? { ...result, checkNow } : null;
}
