import { useState } from "react";
import { dateTime } from "../format";
import { type GitHubRelease, type Latest, available, compareVersions, dismiss, isDismissed, isVersion } from "../updates";
import { type Deployment, useUpdateCheck } from "../useUpdateCheck";
import { AttentionGlyph, UpdateGlyph } from "./Icons";
import { StateBadge } from "./StateBadge";

const RELEASES_PAGE = "https://github.com/Altiward/altiward/releases";

/** Says a fix is a security one: a word and a glyph. */
const SecurityTag = () => <span className="tag attention"><AttentionGlyph /> Security</span>;

export const UpdateAvailable = () => <span className="tag attention"><UpdateGlyph /> Update available</span>;

/** A command with a button that copies it. */
function Command({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // No clipboard access: the command stays selectable.
    }
  }
  return (
    <div className="update-command">
      <code className="data">{text}</code>
      <button type="button" className="button" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
    </div>
  );
}

/** A newer server: what it is, whether it fixes a security problem, and the upgrade steps
 *  from the install guide with its version filled in: upgrade.sh, or on Azure Container
 *  Apps, the app's new image. */
export function ServerNotice({ running, latest, azureApp, onDismiss }: Deployment & {
  running: string; latest: Latest; onDismiss?: () => void;
}) {
  const v = latest.version;
  const guide = azureApp !== undefined
    ? `https://github.com/Altiward/altiward/blob/server-v${v}/deploy/azure/README.md#upgrading`
    : `https://github.com/Altiward/altiward/blob/server-v${v}/docs/install.md#releases-and-updates`;
  return (
    <section className="update-notice" aria-label={`Server ${v} is available`}>
      <div className="update-head">
        <p className="update-title"><UpdateGlyph />Server {v} is available. You’re running {running}.</p>
        {latest.security && <SecurityTag />}
        {onDismiss && <button type="button" className="button" onClick={onDismiss}>Dismiss</button>}
      </div>
      {azureApp !== undefined ? (
        <>
          <p className="hint">
            <a href={latest.url} target="_blank" rel="noreferrer">Release notes for {v}</a>. Read them, then change the
            image of the container app <code>{azureApp}</code>’s <code>altiward</code> container to this one
            (<a href={guide} target="_blank" rel="noreferrer">how to upgrade</a>):
          </p>
          <Command text={`ghcr.io/altiward/altiward-api:${v}`} />
        </>
      ) : (
        <>
          <p className="hint">
            <a href={latest.url} target="_blank" rel="noreferrer">Release notes for {v}</a>. Put the release files in one
            directory on the server, read <code>RELEASE_NOTES.md</code>, then run the upgrade script from your deployment
            directory (<a href={guide} target="_blank" rel="noreferrer">how to upgrade</a>):
          </p>
          <Command text={`./upgrade.sh ~/altiward-${v}`} />
        </>
      )}
    </section>
  );
}

/** A newer agent than any in the fleet, with its package for the MDM. */
export function AgentNotice({ fleet, latest, onDismiss }: { fleet: string; latest: Latest; onDismiss?: () => void }) {
  const v = latest.version;
  const pkg = latest.packageUrl ? decodeURIComponent(latest.packageUrl.split("/").pop() ?? "") : "";
  return (
    <section className="update-notice" aria-label={`Agent ${v} is available`}>
      <div className="update-head">
        <p className="update-title"><UpdateGlyph />Agent {v} is available. The newest in your fleet is {fleet}.</p>
        {latest.security && <SecurityTag />}
        {onDismiss && <button type="button" className="button" onClick={onDismiss}>Dismiss</button>}
      </div>
      <p className="hint">
        {latest.packageUrl
          ? <a href={latest.packageUrl} target="_blank" rel="noreferrer">Download {pkg}</a>
          : <a href={latest.url} target="_blank" rel="noreferrer">Release notes for agent {v}</a>}
        . Roll it out through your MDM after the server.
      </p>
    </section>
  );
}

/** Overview's notices, for admins: newer releases not yet dismissed. Quiet when the check
 *  is off or failed. */
export function UpdateNotices({ fleetAgents }: { fleetAgents: string[] }) {
  const u = useUpdateCheck();
  const [, setDismissed] = useState(0);
  if (u?.state !== "done" || !u.check.releases) return null;
  const a = available(u.running, fleetAgents, u.check.releases);
  const server = a.newerServer && !isDismissed("server", a.newerServer.version) ? a.newerServer : null;
  const agent = a.newerAgent && !isDismissed("agent", a.newerAgent.version) ? a.newerAgent : null;
  if (!server && !agent) return null;
  const hide = (product: "server" | "agent", version: string) => () => { dismiss(product, version); setDismissed((n) => n + 1); };
  return (
    <div className="update-notices">
      {server && <ServerNotice running={u.running} latest={server} azureApp={u.azureApp} onDismiss={hide("server", server.version)} />}
      {agent && a.fleetAgent && <AgentNotice fleet={a.fleetAgent} latest={agent} onDismiss={hide("agent", agent.version)} />}
    </div>
  );
}

/** Where the update check is turned off: the Compose bundle's .env, or the container app. */
function whereSettingsLive(azureApp?: string) {
  return azureApp !== undefined ? "in the container app’s environment variables" : "in the server’s .env";
}

/** Settings' Updates group, for admins: the latest versions, when they were checked, and
 *  the notices, which can't be dismissed here. */
export function UpdatesGroup({ fleetAgents }: { fleetAgents: string[] | null }) {
  const u = useUpdateCheck();
  return (
    <div className="group" role="group" aria-labelledby="updates-title">
      <h3 id="updates-title">Updates</h3>
      {u?.state === "off" && (
        <p className="hint">
          The update check is off: <code>ALTIWARD_UPDATE_CHECK=false</code> is set {whereSettingsLive(u.azureApp)}. New
          releases are listed on <a href={RELEASES_PAGE} target="_blank" rel="noreferrer">GitHub</a>.
        </p>
      )}
      {u?.state === "checking" && <p className="hint" role="status">Checking for updates…</p>}
      {u?.state === "done" && (u.check.releases
        ? <LatestVersions running={u.running} fleetAgents={fleetAgents} releases={u.check.releases} checkedAt={u.check.checkedAt}
          azureApp={u.azureApp} checkNow={u.checkNow} />
        : (
          <div className="box">
            <div className="row">
              <span>
                <StateBadge state="not-granted" label="Couldn’t check for updates" />
                <p className="hint">
                  {u.check.checkedAt ? `Last checked ${dateTime(u.check.checkedAt)}.` : "It hasn’t worked from this browser yet."}
                </p>
                <p className="hint">
                  Your browser asks api.github.com for the release list. A firewall or proxy may block it. New releases are
                  also listed on <a href={RELEASES_PAGE} target="_blank" rel="noreferrer">GitHub</a>.
                </p>
              </span>
              <CheckNow onClick={u.checkNow} />
            </div>
          </div>
        ))}
    </div>
  );
}

/** Asks GitHub again; the check itself keeps it to once a minute. */
const CheckNow = ({ onClick }: { onClick: () => void }) =>
  <button type="button" className="button" onClick={onClick}>Check now</button>;

function LatestVersions({ running, fleetAgents, releases, checkedAt, azureApp, checkNow }: Deployment & {
  running: string; fleetAgents: string[] | null; releases: GitHubRelease[]; checkedAt: string | null; checkNow: () => void;
}) {
  const a = available(running, fleetAgents ?? [], releases);
  const ahead = a.server !== null && isVersion(running) && compareVersions(running, a.server.version) > 0;
  const serverLine = !a.server ? `You’re running ${running}. No server release is published yet.`
    : ahead ? `You’re running ${running}, newer than the latest release, ${a.server.version}.`
    : `You’re running ${running}. The latest release is ${a.server.version}.`;
  const agentLatest = a.agent ? `The latest release is ${a.agent.version}.` : "No agent release is published yet.";
  const agentLine = fleetAgents === null ? agentLatest
    : a.fleetAgent ? `The newest agent in your fleet is ${a.fleetAgent}. ${agentLatest}`
    : `No Mac has reported its agent version yet. ${agentLatest}`;
  return (
    <>
      <div className="box">
        <div className="row" role="group" aria-label="Server">
          <span><span>Server</span><p className="hint">{serverLine}</p></span>
          {a.newerServer ? <UpdateAvailable /> : a.server && isVersion(running) && !ahead && <StateBadge state="verified" label="Up to date" />}
        </div>
        <div className="row" role="group" aria-label="Agent">
          <span><span>Agent</span><p className="hint">{agentLine}</p></span>
          {a.newerAgent ? <UpdateAvailable /> : a.agent && a.fleetAgent && <StateBadge state="verified" label="Up to date" />}
        </div>
      </div>
      <div className="row">
        <p className="hint">
          Last checked {dateTime(checkedAt)}. Your browser asks api.github.com for the release list at most once a
          day after a successful check, and at most once an hour while it can’t reach GitHub or the list doesn’t include
          this server’s version yet. It sends no versions and
          nothing about your Macs. <code>ALTIWARD_UPDATE_CHECK=false</code> {whereSettingsLive(azureApp)} turns it off.
        </p>
        <CheckNow onClick={checkNow} />
      </div>
      {a.newerServer && <ServerNotice running={running} latest={a.newerServer} azureApp={azureApp} />}
      {a.newerAgent && a.fleetAgent && <AgentNotice fleet={a.fleetAgent} latest={a.newerAgent} />}
    </>
  );
}
