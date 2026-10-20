import { createContext, useContext } from "react";
import { type Api, type Me, type Role, can } from "./api";

export const ApiContext = createContext<Api | null>(null);

export function useApi(): Api {
  const api = useContext(ApiContext);
  if (!api) throw new Error("useApi outside ApiContext");
  return api;
}

/** Who is signed in. Views rendered without it (tests) act as an admin. */
export const MeContext = createContext<Me | null>(null);

export function useMe(): Me | null {
  return useContext(MeContext);
}

/** Whether the person signed in may make a change needing role `need`. The server
 *  checks it as well. */
export function useCan(need: Role): boolean {
  const me = useContext(MeContext);
  return me ? can(me.role, need) : true;
}
