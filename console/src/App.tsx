import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { BrowserRouter, NavLink, Navigate, Route, Routes } from "react-router";
import { type Me, createApi, probeSignIn } from "./api";
import { ActivityIcon, CommandsIcon, ElevatedGlyph, EnrollIcon, FleetIcon, NotGrantedGlyph, OverviewIcon, SessionsIcon, SettingsIcon } from "./components/Icons";
import { ApiContext, MeContext, useApi, useMe } from "./context";
import { useDark } from "./theme";
import { useLoad } from "./useLoad";
import { ActivityView } from "./views/Activity";
import { AdminsNowView } from "./views/AdminsNow";
import { CommandsView } from "./views/Commands";
import { EnrollmentsView } from "./views/Enrollments";
import { FleetView } from "./views/Fleet";
import { OverviewView } from "./views/Overview";
import { SessionsView } from "./views/Sessions";
import { SettingsView } from "./views/Settings";

const TOKEN_KEY = "altiward.consoleToken";

function readToken(): string | null {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

function forgetToken() {
  try { sessionStorage.removeItem(TOKEN_KEY); } catch { /* storage blocked */ }
}

/** Why the sign-in page is showing, when it isn't the first visit. */
type Problem = "token" | "ended" | string;

/** What signing in through single sign-on can come back with (?sso_error=), in words. */
const ssoProblems: Record<string, string> = {
  no_role: "Your account isn’t in a group that can use Altiward. Ask your Altiward administrator to add you.",
  groups: "Your identity provider didn’t send your groups, which happens to people in a great many groups. " +
    "Ask your administrator to send only the groups assigned to Altiward.",
  expired: "Signing in took too long. Try again.",
  denied: "Your identity provider didn’t sign you in. Try again, or ask your administrator.",
  unavailable: "Altiward can’t reach your identity provider. Try again shortly, or use a break-glass token.",
  failed: "Signing in didn’t work. Try again. If it keeps failing, ask your administrator to check the Altiward server’s log.",
  token: "The server rejected that token. Check it and paste it again.",
  ended: "Your session ended. Sign in again.",
};

/** The ?sso_error= the server sent the browser back with, removed from the address once read. */
function takeSSOProblem(): string | null {
  const params = new URLSearchParams(window.location.search);
  const problem = params.get("sso_error");
  if (problem) {
    params.delete("sso_error");
    const rest = params.size ? `?${params}` : "";
    window.history.replaceState(null, "", window.location.pathname + rest + window.location.hash);
  }
  return problem;
}

type SignedIn = { me: Me; token?: string };

export function App() {
  const [checking, setChecking] = useState(true);
  const [sso, setSSO] = useState(false);
  const [signedIn, setSignedIn] = useState<SignedIn | null>(null);
  const [problem, setProblem] = useState<Problem | null>(takeSSOProblem);

  const ended = useCallback((why: Problem) => {
    forgetToken();
    setSignedIn(null);
    setProblem(why);
  }, []);
  const api = useMemo(() => {
    if (!signedIn) return null;
    const onUnauthorized = () => ended(signedIn.token ? "token" : "ended");
    return signedIn.token ? createApi({ token: signedIn.token }, { onUnauthorized })
      : createApi({ csrf: signedIn.me.csrf_token ?? "" }, { onUnauthorized });
  }, [signedIn, ended]);

  const signInWithToken = useCallback(async (token: string) => {
    try {
      const me = await createApi({ token }).me();
      try { sessionStorage.setItem(TOKEN_KEY, token); } catch { /* keep it in memory only */ }
      setProblem(null);
      setSignedIn({ me, token });
    } catch {
      ended("token");
    }
  }, [ended]);

  useEffect(() => {
    let live = true;
    (async () => {
      const found = await probeSignIn();
      if (!live) return;
      setSSO(found.sso);
      const token = readToken();
      if (found.me && !token) setSignedIn({ me: found.me });
      else if (token) await signInWithToken(token);
      if (live) setChecking(false);
    })();
    return () => { live = false; };
  }, [signInWithToken]);

  const signOut = useCallback(async () => {
    if (api && !signedIn?.token) await api.signOut().catch(() => undefined);
    forgetToken();
    setSignedIn(null);
    setProblem(null);
  }, [api, signedIn]);

  if (checking) return <div className="signin" aria-busy="true" />;
  if (!api || !signedIn) return <SignIn sso={sso} problem={problem} onToken={signInWithToken} />;
  return (
    <ApiContext.Provider value={api}>
      <MeContext.Provider value={signedIn.me}>
        <BrowserRouter>
          <Window onSignOut={signOut} />
        </BrowserRouter>
      </MeContext.Provider>
    </ApiContext.Provider>
  );
}

function Window({ onSignOut }: { onSignOut: () => void }) {
  const api = useApi();
  const pending = useLoad(() => api.enrollments({ status: "pending" }), [], 30_000);
  const waiting = pending.data?.length ?? 0;
  const about = useLoad(() => api.about(), []);
  return (
    <div className="window">
      <nav className="sidebar" aria-label="Sections">
        <Lockup />
        <h2>Monitor</h2>
        <Item to="/overview" icon={<OverviewIcon />}>Overview</Item>
        <Item to="/admins" icon={<ElevatedGlyph />}>Admins now</Item>
        <Item to="/sessions" icon={<SessionsIcon />}>Sessions</Item>
        <Item to="/fleet" icon={<FleetIcon />}>Fleet</Item>
        <h2>Manage</h2>
        <Item to="/enrollments" icon={<EnrollIcon />}
          badge={waiting ? <span className="count" aria-label={`${waiting} waiting for approval`}>{waiting}</span> : null}>
          Enrollments
        </Item>
        <Item to="/commands" icon={<CommandsIcon />}>Commands</Item>
        <Item to="/activity" icon={<ActivityIcon />}>Activity</Item>
        <Item to="/settings" icon={<SettingsIcon />}>Settings</Item>
        <Account onSignOut={onSignOut} />
        {about.data && <p className="version">Altiward {about.data.version}</p>}
      </nav>
      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<OverviewView />} />
          <Route path="/admins" element={<AdminsNowView />} />
          <Route path="/sessions" element={<SessionsView />} />
          <Route path="/fleet" element={<FleetView />} />
          <Route path="/enrollments" element={<EnrollmentsView onChanged={pending.reload} />} />
          <Route path="/commands" element={<CommandsView />} />
          <Route path="/activity" element={<ActivityView />} />
          <Route path="/settings" element={<SettingsView />} />
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Routes>
      </main>
    </div>
  );
}

/** Mark plus name. The mark file follows the appearance, chosen or the system's; below 24px
 *  the brand uses the mark alone. */
function Lockup() {
  const dark = useDark();
  return (
    <div className="lockup">
      <img src={dark ? "/brand/altiward-mark-on-dark.svg" : "/brand/altiward-mark.svg"} alt="" width={24} height={24} />
      <span>Altiward</span>
    </div>
  );
}

function Item({ to, icon, badge, children }: { to: string; icon: ReactNode; badge?: ReactNode; children: ReactNode }) {
  return (
    <NavLink to={to} className={({ isActive }) => (isActive ? "active" : undefined)}>
      {icon}<span>{children}</span>{badge}
    </NavLink>
  );
}

const roleNames = { viewer: "Viewer", operator: "Operator", admin: "Admin" } as const;

/** Who is signed in, their role, and signing out. */
function Account({ onSignOut }: { onSignOut: () => void }) {
  const me = useMe();
  if (!me) return null;
  const who = me.method === "sso" ? (me.name || me.actor)
    : me.actor.startsWith("break-glass:") ? "Break-glass token" : "Console token";
  return (
    <div className="account">
      <p className="who" title={me.actor}>{who}</p>
      <p className="role">{roleNames[me.role]}</p>
      <button type="button" className="button" onClick={onSignOut}>Sign out</button>
    </div>
  );
}

function SignIn({ sso, problem, onToken }: { sso: boolean; problem: Problem | null; onToken: (token: string) => void }) {
  const [value, setValue] = useState("");
  const [showToken, setShowToken] = useState(!sso || problem === "token");
  const message = problem ? (ssoProblems[problem] ?? ssoProblems.failed) : null;
  const next = window.location.pathname + window.location.search;
  return (
    <div className="signin">
      <form onSubmit={(e) => { e.preventDefault(); if (value.trim()) onToken(value.trim()); }}>
        <Lockup />
        <h1>Sign in</h1>
        {message && <p className="field-error" role="alert"><NotGrantedGlyph /> <span>{message}</span></p>}
        {sso && (
          <>
            <p>Sign in with your organization’s account.</p>
            <div className="buttons">
              <a className="button primary" href={`/v1/auth/login?next=${encodeURIComponent(next)}`}>Sign in with single sign-on</a>
            </div>
            {!showToken && (
              <p className="alternative">
                <button type="button" className="link" onClick={() => setShowToken(true)}>Use a break-glass token instead</button>
              </p>
            )}
          </>
        )}
        {showToken && (
          <div className={sso ? "break-glass" : undefined}>
            <p>{sso ? "Only for when single sign-on isn’t working. Each use is recorded." : "Paste the console token your Altiward administrator gave you."}</p>
            <label>
              <span className="secondary small" style={{ display: "block", marginBottom: 4 }}>{sso ? "Break-glass token" : "Console token"}</span>
              <input type="password" autoComplete="off" autoFocus={!sso} value={value} onChange={(e) => setValue(e.target.value)} />
            </label>
            <div className="buttons"><button type="submit" className={`button${sso ? "" : " primary"}`} disabled={!value.trim()}>Sign in</button></div>
          </div>
        )}
      </form>
    </div>
  );
}
