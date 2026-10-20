import { useEffect, useRef } from "react";
import type { Command } from "./api";
import { useApi } from "./context";

/**
 * Follows a queued command until its Mac reports back or it expires, then calls `onDone`
 * once. Asks only while the page is visible, like useLoad's refresh.
 */
export function useCommandResult(command: Command | null, onDone: (c: Command) => void, everyMs = 3000) {
  const api = useApi();
  const done = useRef(onDone);
  done.current = onDone;

  useEffect(() => {
    if (!command || command.status !== "pending") return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function check() {
      if (document.visibilityState === "visible") {
        try {
          const c = await api.command(command!.command_id);
          if (stopped) return;
          if (c.status !== "pending") return done.current(c);
        } catch {
          // Ask again next time.
        }
      }
      if (!stopped) timer = setTimeout(check, everyMs);
    }
    void check();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [api, command, everyMs]);
}
