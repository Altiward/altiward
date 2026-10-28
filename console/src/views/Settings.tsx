import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router";
import type { ConsoleSignIn, ExportSink, HistoryPolicy, MDMCheck, MDMStatus, Settings } from "../api";
import { Banner, Details, Missing, RoleNote, Segmented, Toolbar } from "../components/Chrome";
import { StateBadge } from "../components/StateBadge";
import { ConfirmSheet } from "../components/Sheet";
import { Command, UpdatesGroup } from "../components/Updates";
import { useApi, useCan } from "../context";
import { dateOnly, dateTime, sinkName } from "../format";
import { type SiemGuide, type Where, siemGuides, siemSnippet } from "../siemSetup";
import { appearances, setLook, themes, useLook } from "../theme";
import { useLoad } from "../useLoad";

/** The server's default when silent_after_hours is 0 (store.DefaultSilentAfterHours). */
const DEFAULT_SILENT_HOURS = 72;
const MAX_SILENT_HOURS = 720;

/** The server's bounds and default for history_days (store.MinHistoryDays and the others). */
const MIN_HISTORY_DAYS = 90;
const MAX_HISTORY_DAYS = 3650;
const DEFAULT_HISTORY_DAYS = 365;
const KEPT_FOR_GOOD = -1;

type HistoryChoice = "default" | "days" | "good";

/** The days in the stored history_days, as the choice and the number shown for it. */
function choiceOf(historyDays: number | undefined): { choice: HistoryChoice; days: string } {
  if (historyDays === KEPT_FOR_GOOD) return { choice: "good", days: String(DEFAULT_HISTORY_DAYS) };
  if (historyDays) return { choice: "days", days: String(historyDays) };
  return { choice: "default", days: String(DEFAULT_HISTORY_DAYS) };
}

/** The policy in force, in words. */
function policySentence(p: HistoryPolicy): string {
  switch (p.reason) {
    case "default_siem": return "1 year, the default with a SIEM connected";
    case "default_no_siem": return "Kept for good: no SIEM is connected";
    case "kept_for_good": return "Kept for good";
    default: return p.days === 1 ? "1 day" : `${p.days} days`;
  }
}

/** What a period set by hand does to the history the default holds back for the SIEM. */
function heldWarning(heldBefore: string): string {
  return `A period you set also removes history from before ${dateOnly(heldBefore)}, which your SIEM may not have.`;
}

/** Days of history kept; Infinity when nothing is removed. */
function keptDays(p: HistoryPolicy): number {
  return p.kept_for_good || p.days <= 0 ? Infinity : p.days;
}

/** Settings' tabs, as in a Mac app's Settings window. Each has its own address under
 *  /settings, so the install guide and other pages can link to one. Sign-ins and Updates are
 *  for admins only. */
const TABS = [
  { to: "/settings", title: "General" },
  { to: "/settings/siem", title: "SIEM export" },
  { to: "/settings/mdm", title: "MDM" },
  { to: "/settings/sign-ins", title: "Sign-ins", admin: true },
  { to: "/settings/updates", title: "Updates", admin: true },
];

/** The body of a settings update. PUT replaces every setting, so a change sends the rest as
 *  loaded, apart from the history period: the server keeps the stored one when it is left out,
 *  so only a change to it sends it, and a stale page can't put back a period changed elsewhere. */
function withChange(loaded: Settings, change: Partial<Settings>): Settings {
  const { history_days: _stored, ...rest } = loaded;
  return { ...rest, ...change };
}

/** The guide on GitHub for the server that's running, or main for a build without a release version. */
const guideRef = (version: string | null) => (version && /^\d+\.\d+\.\d+(-rc\.\d+)?$/.test(version) ? `server-v${version}` : "main");

export function SettingsView() {
  const admin = useCan("admin");
  return (
    <>
      <Toolbar title="Settings">
        <nav className="segmented" aria-label="Settings sections">
          {TABS.filter((t) => admin || !t.admin).map((t) => (
            <NavLink key={t.to} to={t.to} end>{t.title}</NavLink>
          ))}
        </nav>
      </Toolbar>
      <div className="pane">
        <div className="form">
          <Routes>
            <Route index element={<GeneralSettings />} />
            <Route path="siem" element={<SiemExport />} />
            <Route path="mdm" element={<MdmSettings />} />
            {admin && <Route path="sign-ins" element={<ConsoleSignIns />} />}
            {admin && <Route path="updates" element={<Updates />} />}
            <Route path="*" element={<Navigate to="/settings" replace />} />
          </Routes>
        </div>
      </div>
    </>
  );
}

/** Enrollment and alert settings, which only admins change, and this browser's appearance. */
function GeneralSettings() {
  const api = useApi();
  const { data, error, reload } = useLoad(() => api.settings(), []);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [hours, setHours] = useState("");
  const policy = useLoad(() => api.retention().then((r) => r.history), []);
  // Whether a SIEM is connected decides what the default period would be; null when unknown.
  const sinks = useLoad(() => api.exports().catch(() => null), []);
  const [historyChoice, setHistoryChoice] = useState<HistoryChoice>("default");
  const [historyDays, setHistoryDays] = useState(String(DEFAULT_HISTORY_DAYS));
  const [removing, setRemoving] = useState<{ value: number; days: number; heldBefore: string | null } | null>(null);

  useEffect(() => {
    if (data) setHours(String(data.silent_after_hours || DEFAULT_SILENT_HOURS));
  }, [data]);

  // The history choice follows the stored period, and only that: a choice not saved yet stays
  // when another setting saves and the settings load again.
  const storedHistory = data?.history_days;
  const loaded = !!data;
  useEffect(() => {
    if (!loaded) return;
    const c = choiceOf(storedHistory);
    setHistoryChoice(c.choice);
    setHistoryDays(c.days);
  }, [loaded, storedHistory]);

  async function save(change: Partial<Settings>) {
    if (!data) return;
    setSaving(true);
    try {
      await api.putSettings(withChange(data, change));
      setSaveError(null);
      await reload();
      await policy.reload();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  const canChange = useCan("admin");
  const parsed = Number(hours);
  const hoursValid = /^\d+$/.test(hours) && parsed >= 1 && parsed <= MAX_SILENT_HOURS;
  const hoursChanged = !!data && hoursValid && parsed !== (data.silent_after_hours || DEFAULT_SILENT_HOURS);

  const parsedDays = Number(historyDays);
  const historyValid = historyChoice !== "days"
    || (/^\d+$/.test(historyDays) && parsedDays >= MIN_HISTORY_DAYS && parsedDays <= MAX_HISTORY_DAYS);
  const newHistory = historyChoice === "good" ? KEPT_FOR_GOOD : historyChoice === "days" ? parsedDays : 0;
  const historyChanged = !!data && historyValid && newHistory !== (data.history_days ?? 0);
  // How many days the choice would keep: Infinity for good. The default depends on the SIEM; when
  // that is unknown, count it as a year so a possible removal is confirmed.
  const siem = sinks.data ? sinks.data.length > 0 : null;
  const newDays = historyChoice === "good" ? Infinity
    : historyChoice === "days" ? parsedDays
    : siem === false ? Infinity : DEFAULT_HISTORY_DAYS;
  // Without the policy in force, any finite period might remove history, so it asks.
  const shortens = newDays < (policy.data ? keptDays(policy.data) : Infinity);
  // While the default holds back history from before the SIEM was connected, a number of days
  // releases it whatever the number, so that asks too. Keeping for good removes nothing.
  const heldBefore = policy.data?.held_before ?? null;
  const releasesHold = !!heldBefore && historyChoice === "days";

  function saveHistory() {
    if (!historyChanged) return;
    if (shortens || releasesHold) setRemoving({ value: newHistory, days: newDays, heldBefore: releasesHold ? heldBefore : null });
    else void save({ history_days: newHistory });
  }

  return (
    <>
      {(error || saveError || policy.error) && <Banner>{saveError ?? error ?? policy.error}</Banner>}
      {!canChange && <RoleNote>Changing settings needs the admin role.</RoleNote>}
      {removing && (
        <ConfirmSheet title="Remove older history?" confirm="Remove" destructive busy={saving}
          message={`History older than ${removing.days} days will be removed at the next daily run. Your SIEM keeps what it was sent.`
            + (removing.heldBefore ? ` ${heldWarning(removing.heldBefore)}` : "")}
          onConfirm={() => { const value = removing.value; setRemoving(null); void save({ history_days: value }); }}
          onCancel={() => setRemoving(null)} />
      )}
      <div className="group" style={{ marginTop: 0 }}>
        <h3>Enrollment</h3>
        <div className="box">
          <label className="row">
            <span>
              <span>Approve Macs that enrol again</span>
              <p className="hint">
                On by default and recommended. A new key for a Mac that enrolled before waits for approval
                in Enrollments; its active key keeps reporting. Retired Macs always need approval for a
                new key. Turning this off lets anyone with the enrolment token replace an enrolled Mac's
                identity by naming its serial and hardware UUID.
                First enrolments still use the shared token: check them against your device inventory, or
                approve every new Mac.
              </p>
            </span>
            <input type="checkbox" role="switch" disabled={!data || saving || !canChange}
              checked={data?.reenrollment_requires_approval ?? true}
              onChange={(e) => save({ reenrollment_requires_approval: e.target.checked })} />
          </label>
          <label className="row">
            <span>
              <span>Approve every new Mac</span>
              <p className="hint">
                Off by default. A Mac's first key waits for approval in Enrollments too, so the shared
                enrolment token can't add a Mac, or take a serial before the real Mac enrols. Expect one
                approval for each Mac during a rollout.
              </p>
            </span>
            <input type="checkbox" role="switch" disabled={!data || saving || !canChange}
              checked={data?.new_mac_requires_approval ?? false}
              onChange={(e) => save({ new_mac_requires_approval: e.target.checked })} />
          </label>
        </div>
      </div>
      <div className="group">
        <h3>Alerts</h3>
        <div className="box">
          <label className="row">
            <span>
              <span>Alert when a Mac stops checking in</span>
              <p className="hint">
                Off: no new alerts, for example if your SIEM already watches for quiet Macs. A Mac already
                reported still sends a resolved alert when it checks in again.
              </p>
            </span>
            <input type="checkbox" role="switch" disabled={!data || saving || !canChange}
              checked={!(data?.silent_alerts_off ?? false)}
              onChange={(e) => save({ silent_alerts_off: !e.target.checked })} />
          </label>
          <form className="row" onSubmit={(e) => { e.preventDefault(); if (hoursChanged) save({ silent_after_hours: parsed }); }}>
            <label htmlFor="silent-hours">
              <span>Raise it after</span>
              <p className="hint">
                Hours without a check-in before Altiward raises an alert and sends it to your SIEM. Laptops that are
                closed stop checking in too, so the default of {DEFAULT_SILENT_HOURS} hours rides out a weekend.
                Macs whose enrollments you revoked never alert.
              </p>
            </label>
            <span className="inline-field">
              <input id="silent-hours" type="number" inputMode="numeric" min={1} max={MAX_SILENT_HOURS}
                disabled={!data || saving || !canChange || data.silent_alerts_off} value={hours} aria-invalid={!hoursValid}
                onChange={(e) => setHours(e.target.value)} />
              <span className="secondary">hours</span>
              <button type="submit" className="button" disabled={!hoursChanged || saving || !canChange || data?.silent_alerts_off}>Save</button>
            </span>
          </form>
          {!hoursValid && <p className="hint" role="alert">Enter a whole number of hours from 1 to {MAX_SILENT_HOURS}.</p>}
        </div>
      </div>
      <div className="group">
        <h3>History</h3>
        <div className="box">
          <form className="row" onSubmit={(e) => { e.preventDefault(); saveHistory(); }}>
            <div>
              <label htmlFor="history-choice">Keep history for</label>
              {policy.data && (
                <>
                  <p className="hint">{policySentence(policy.data)}</p>
                  {policy.data.held_before && (
                    <>
                      <p className="hint">
                        History from before {dateOnly(policy.data.held_before)}, when your SIEM was connected, is kept until you
                        replay it to the SIEM.
                      </p>
                      <p className="hint">{heldWarning(policy.data.held_before)}</p>
                    </>
                  )}
                  {policy.data.waiting_for_backfill && (
                    <p className="hint">Nothing is removed until the admin group has been sent to your SIEM.</p>
                  )}
                </>
              )}
              <p className="hint">
                A shorter period removes older history at the next daily run. Your SIEM keeps what it was sent.
              </p>
            </div>
            <span className="inline-field">
              <select id="history-choice" disabled={!data || saving || !canChange} value={historyChoice}
                onChange={(e) => setHistoryChoice(e.target.value as HistoryChoice)}>
                <option value="default">Default</option>
                <option value="days">Days</option>
                <option value="good">Keep for good</option>
              </select>
              {historyChoice === "days" && (
                <>
                  <input type="number" inputMode="numeric" min={MIN_HISTORY_DAYS} max={MAX_HISTORY_DAYS}
                    aria-label="Days of history" disabled={!data || saving || !canChange} value={historyDays}
                    aria-invalid={!historyValid} onChange={(e) => setHistoryDays(e.target.value)} />
                  <span className="secondary">days</span>
                </>
              )}
              <button type="submit" className="button" aria-label="Save history period"
                disabled={!historyChanged || saving || !canChange}>Save</button>
            </span>
          </form>
          {!historyValid && (
            <p className="hint" role="alert">Enter a whole number of days from {MIN_HISTORY_DAYS} to {MAX_HISTORY_DAYS}.</p>
          )}
        </div>
      </div>
      <AppearanceGroup />
      <p className="hint">
        Altiward includes open-source software. <a href="/third-party-notices.txt">Third-party notices</a>
      </p>
    </>
  );
}

/** The console's theme and light or dark, for this browser only, so any role can change it. */
function AppearanceGroup() {
  const look = useLook();
  return (
    <div className="group" role="group" aria-labelledby="appearance-title">
      <h3 id="appearance-title">Appearance</h3>
      <div className="box">
        <div className="row">
          <span>
            <span>Theme</span>
            <p className="hint">Status colours mean the same in every theme.</p>
          </span>
          <Segmented label="Theme" options={themes} value={look.theme} onChange={(theme) => setLook({ theme })} />
        </div>
        <div className="row">
          <span>
            <span>Light or dark</span>
            <p className="hint">System follows your Mac.</p>
          </span>
          <Segmented label="Light or dark" options={appearances} value={look.appearance}
            onChange={(appearance) => setLook({ appearance })} />
        </div>
      </div>
      <p className="hint">Saved in this browser, for you only.</p>
    </div>
  );
}

/** Each SIEM's queue, with a test event and a retry for after a fix, and how to connect the
 *  others. The SIEMs themselves are set in the server's environment, so nothing here changes
 *  their settings. */
function SiemExport() {
  const api = useApi();
  const canAct = useCan("admin");
  const { data, error, reload } = useLoad(() => api.exports(), []);
  const { data: about } = useLoad(() => api.about(), []);
  const where: Where = about?.platform === "azure-container-apps" ? { azureApp: about.app ?? "" } : {};
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function act(action: () => Promise<string>) {
    setBusy(true);
    try {
      setResult(await action());
      setActionError(null);
      await reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  const sendTest = () => act(async () => {
    const r = await api.testExport();
    return `Test event queued for ${r.queued_for.map(sinkName).join(" and ")}. It shows up there as console.test_export, usually within a few minutes.`;
  });
  const retry = (sink: string) => act(async () => {
    const r = await api.retryExports(sink);
    return `Retrying ${r.retried} waiting for ${sinkName(sink)} now.`;
  });

  return (
    <div className="group" role="group" aria-labelledby="siem-title">
      <h3 id="siem-title">SIEM export</h3>
      {(error || actionError) && <Banner>{actionError ?? error}</Banner>}
      {data && data.length === 0 && <p className="hint">No SIEM is connected.</p>}
      {data && data.length > 0 && (
        <div className="box">
          {data.map((s) => <SinkRow key={s.sink} sink={s} canAct={canAct} busy={busy}
            onRetry={() => retry(s.sink)} />)}
          <div className="row">
            <span>
              <span>Send a test event</span>
              <p className="hint">Sends a console action to every SIEM above, through the same queue as real events.</p>
            </span>
            <button type="button" className="button" disabled={busy || !canAct} onClick={sendTest}>Send test event</button>
          </div>
        </div>
      )}
      {result && <p className="hint" role="status">{result}</p>}
      {data && <ConnectSiem connected={data.map((s) => s.sink)} where={where} version={about?.version ?? null} />}
    </div>
  );
}

/** For each SIEM not connected yet: the settings it needs, and lines to copy to where the
 *  server's settings live. Read-only, and only placeholders: SIEM settings belong to the
 *  deployment, so changing where events go needs the server, not a console session. */
function ConnectSiem({ connected, where, version }: { connected: string[]; where: Where; version: string | null }) {
  const guides = siemGuides(where).filter((g) => !connected.includes(g.sink));
  if (guides.length === 0) return null;
  const ref = guideRef(version);
  const azure = where.azureApp !== undefined;
  return (
    <div className="siem-connect">
      <h4>{connected.length > 0 ? "Connect another SIEM" : "Connect a SIEM"}</h4>
      <p className="hint">
        {azure
          ? "SIEM settings are environment variables on the container app’s altiward container, with secrets kept as app secrets. Setting them starts a new revision."
          : "SIEM settings go in the server’s .env, then run docker compose up -d."}{" "}
        They can’t be changed here: changing where events go takes access to the server, not just the console.
      </p>
      {guides.map((g) => <SiemGuideDetails key={g.sink} guide={g} where={where} docs={`https://github.com/Altiward/altiward/blob/${ref}/${g.guide}`} />)}
    </div>
  );
}

function SiemGuideDetails({ guide, where, docs }: { guide: SiemGuide; where: Where; docs: string }) {
  const name = sinkName(guide.sink);
  const azure = where.azureApp !== undefined;
  const optional = guide.settings.filter((s) => !s.required);
  return (
    <details className="siem-guide">
      <summary>{name}</summary>
      <p className="hint">{guide.intro} <a href={docs} target="_blank" rel="noreferrer">{name} setup guide</a>.</p>
      <p className="hint">
        {azure
          ? "Run these with the Azure CLI, after filling in the values in angle brackets."
          : "Add these lines to .env, after filling in the values in angle brackets. Uncomment an optional one to change it."}
      </p>
      <Command text={siemSnippet(guide, where)} />
      {azure && optional.length > 0 && (
        <>
          <p className="hint">Optional settings, added the same way:</p>
          <ul className="hint siem-optional" aria-label={`Optional ${name} settings`}>
            {optional.map((s) => <li key={s.name}><code>{s.name}</code>. {s.what}.</li>)}
          </ul>
        </>
      )}
    </details>
  );
}

function SinkRow({ sink, canAct, busy, onRetry }: {
  sink: ExportSink; canAct: boolean; busy: boolean; onRetry: () => void;
}) {
  const failing = sink.failing > 0;
  const since = sink.oldest_queued_at ? ` The oldest has waited since ${dateTime(sink.oldest_queued_at)}.` : "";
  const status = failing
    ? `${sink.pending} waiting, ${sink.failing} of them failed.${since}`
    : sink.pending > 0 ? `${sink.pending} waiting to be sent.` : "Nothing waiting.";
  const delivered = sink.last_delivered_at ? `Last delivered ${dateTime(sink.last_delivered_at)}.` : "Nothing delivered yet.";
  return (
    <div className="row" role="group" aria-label={sinkName(sink.sink)}>
      <span>
        <span>{sinkName(sink.sink)}</span>
        <p className="hint">{status} {delivered}</p>
        {failing && sink.last_error && <p className="hint"><code>{sink.last_error}</code></p>}
      </span>
      <span className="inline-field">
        {failing
          ? <StateBadge state="not-granted" label="Failing" />
          : sink.pending > 0 ? <StateBadge state="claimed" label="Sending" /> : <StateBadge state="verified" label="Up to date" />}
        {failing && <button type="button" className="button" disabled={busy || !canAct} onClick={onRetry}>Retry now</button>}
      </span>
    </div>
  );
}

/** How the Macs that didn't match Intune are described, by the outcome of their check. */
const unmatchedWords: Record<Exclude<MDMCheck, "match">, string> = {
  not_sent: "sent no Intune device ID",
  invalid_id: "sent an invalid device ID",
  mismatch: "sent another Mac's device ID",
  unknown_id: "sent a device ID Intune doesn't know",
  unavailable: "enrolled while Intune couldn't be reached",
};

/** "1 active Mac" or "2 active Macs". */
const activeMacs = (n: number) => `${n} active Mac${n === 1 ? "" : "s"}`;

/** What the counts of active Macs say: how many were checked and matched, and how many were never
 *  checked. A Mac is checked only when it enrols a key, so those that enrolled before Intune was
 *  connected wait for their next key. */
const checkedSentence = (checked: number, count: number, verb: "matched" | "didn’t match") =>
  `Of the ${activeMacs(checked)} checked since Intune was connected, ${count} ${verb} Intune.`;
const notCheckedSentence = (n: number) =>
  `${activeMacs(n)} enrolled before Intune was connected and ${n === 1 ? "hasn’t" : "haven’t"} been checked`;

/** Whether the last sync failed: its error is newer than its last success. */
const syncFailing = (s: MDMStatus) =>
  !!s.last_error_at && (!s.last_success_at || new Date(s.last_error_at) > new Date(s.last_success_at));

/** Microsoft Intune: whether it is connected and syncing, how many active Macs matched it when
 *  they enrolled, and the setting that holds the rest for approval. Like the SIEMs, the
 *  connection is set in the server's environment, so nothing here changes it. */
function MdmSettings() {
  const api = useApi();
  const canChange = useCan("admin");
  const status = useLoad(() => api.mdmStatus(), []);
  const settings = useLoad(() => api.settings(), []);
  const { data: about } = useLoad(() => api.about(), []);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  const s = status.data;
  const checks = s?.checks ?? {};
  const matched = checks.match ?? 0;
  const checked = Object.values(checks).reduce((sum, n) => sum + (n ?? 0), 0);
  const unmatched = checked - matched;
  const notChecked = s?.not_checked ?? 0;
  // A later server may count an outcome this console has no words for.
  const unnamed = Object.entries(checks)
    .filter(([k]) => k !== "match" && !(k in unmatchedWords)).reduce((sum, [, n]) => sum + (n ?? 0), 0);
  const rest = [
    ...(Object.keys(unmatchedWords) as (keyof typeof unmatchedWords)[])
      .filter((k) => checks[k]).map((k) => `${checks[k]} ${unmatchedWords[k]}`),
    ...(unnamed ? [`${unnamed} had another outcome`] : []),
  ];
  const guide = `https://github.com/Altiward/altiward/blob/${guideRef(about?.version ?? null)}/docs/install.md#7-connect-intune-optional`;

  async function setRequired(on: boolean) {
    if (!settings.data) return;
    setSaving(true);
    setConfirming(false);
    try {
      await api.putSettings(withChange(settings.data, { require_intune_match: on }));
      setSaveError(null);
      await settings.reload();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <div className="group" role="group" aria-labelledby="mdm-title" style={{ marginTop: 0 }}>
        <h3 id="mdm-title">Microsoft Intune</h3>
        {(status.error || settings.error || saveError) && <Banner>{saveError ?? status.error ?? settings.error}</Banner>}
        {s && !s.configured && (
          <div className="box">
            <div className="row">
              <span>
                <span>Intune</span>
                <p className="hint">
                  Connecting Intune lets Altiward check each Mac that enrols against the Macs Intune manages, and shows
                  each Mac's primary user in Fleet. Like a SIEM, it is set in the server's environment, not here.{" "}
                  <a href={guide} target="_blank" rel="noreferrer">Connect Intune</a>.
                </p>
              </span>
              <StateBadge state="ended" label="Not connected" />
            </div>
          </div>
        )}
        {s?.configured && (
          <>
            <Details rows={[
              ["Sync", syncFailing(s) ? <StateBadge key="sync" state="not-granted" label="Failing" />
                : s.last_success_at ? <StateBadge key="sync" state="verified" label="Synced" />
                : <StateBadge key="sync" state="claimed" label="Waiting for the first sync" />],
              ["Macs in Intune", String(s.devices ?? 0)],
              ["Last synced", s.last_success_at ? dateTime(s.last_success_at) : <Missing key="synced">Not yet</Missing>],
              ["Last error", s.last_error
                ? <span key="error"><code>{s.last_error}</code>{s.last_error_at && <span className="secondary"> ({dateTime(s.last_error_at)})</span>}</span>
                : <Missing key="error">None</Missing>],
            ]} />
            <p className="hint">
              {checked === 0
                ? "No active Mac has enrolled with Intune connected yet, so none has been checked."
                : checkedSentence(checked, matched, "matched")}
            </p>
            {rest.length > 0 && <p className="hint">Of the rest, {rest.join(", ")}.</p>}
            {notChecked > 0 && (
              <p className="hint">{notCheckedSentence(notChecked)}: a Mac is checked when it next enrols a key.</p>
            )}
          </>
        )}
      </div>
      {s?.configured && (
        <div className="group">
          <h3>Enrolment</h3>
          {!canChange && <RoleNote>Changing settings needs the admin role.</RoleNote>}
          <div className="box">
            <label className="row">
              <span>
                <span>Require an Intune match</span>
                <p className="hint">
                  Off by default. A new key waits for approval in Enrollments unless the device ID the Mac sent matched
                  Intune: a Mac that sent none, an invalid or unknown ID, or that Intune couldn't be asked about waits too.
                  A key sent with another Mac's device ID waits whatever this says. Keys already in use keep working.
                </p>
              </span>
              <input type="checkbox" role="switch" disabled={!settings.data || saving || !canChange}
                checked={settings.data?.require_intune_match ?? false}
                onChange={(e) => (e.target.checked && (unmatched > 0 || notChecked > 0) ? setConfirming(true) : void setRequired(e.target.checked))} />
            </label>
          </div>
        </div>
      )}
      {confirming && (
        <ConfirmSheet title="Require an Intune match?" confirm="Require a match" busy={saving}
          message={[
            ...(unmatched > 0 ? [checkedSentence(checked, unmatched, "didn’t match")] : []),
            ...(notChecked > 0 ? [`${notCheckedSentence(notChecked)}.`] : []),
            "Their keys keep working, but from now on a new key from a Mac that doesn’t match waits for your approval in Enrollments.",
          ].join(" ")}
          onConfirm={() => void setRequired(true)} onCancel={() => setConfirming(false)} />
      )}
    </>
  );
}

/** Whether a newer server or agent is out, against the agents in the fleet. Admins only. */
function Updates() {
  const api = useApi();
  const { data } = useLoad(() => api.devices(), []);
  return <UpdatesGroup fleetAgents={data ? data.map((d) => d.agent_version) : null} />;
}

/** Who is signed in to the console, for an admin to end a sign-in early. Admins only. */
function ConsoleSignIns() {
  const api = useApi();
  const { data, error, reload } = useLoad(() => api.consoleSessions(), []);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function end(s: ConsoleSignIn) {
    setBusy(true);
    try {
      await api.endConsoleSession(s.id);
      setResult(`${s.name} is signed out. They can sign in again unless you remove them at your identity provider.`);
      setActionError(null);
      await reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="group" role="group" aria-labelledby="signins-title">
      <h3 id="signins-title">Signed in to the console</h3>
      {(error || actionError) && <Banner>{actionError ?? error}</Banner>}
      {data && data.length === 0 && <p className="hint">Nobody is signed in through single sign-on.</p>}
      {data && data.length > 0 && (
        <div className="box">
          {data.map((s) => {
            const name = s.current ? `${s.name} (you)` : s.name;
            return (
              <div key={s.id} className="row" role="group" aria-label={name}>
                <span>
                  <span>{name}</span>
                  <p className="hint">
                    {s.actor} · {s.role} · signed in {dateTime(s.created_at)}, ends by {dateTime(s.ends_at)}
                  </p>
                </span>
                {!s.current && (
                  <button type="button" className="button" disabled={busy} onClick={() => end(s)}>End sign-in</button>
                )}
              </div>
            );
          })}
        </div>
      )}
      <p className="hint">
        After a role change at your identity provider, end the person’s sign-in so the new role applies now.
        Break-glass tokens have no sign-in to end, so they aren’t listed: Activity shows when one is used.
      </p>
      {result && <p className="hint" role="status">{result}</p>}
    </div>
  );
}
