# Changelog

Release notes for the Altiward server and the Mac agent, newest first. Releases are
published on GitHub, and each release's section
is its notes.

Each release has one section headed `## Server X.Y.Z - YYYY-MM-DD` or
`## Agent X.Y.Z - YYYY-MM-DD`. Write `unreleased` instead of the date until the day it
ships: the release workflows refuse a version whose section is missing or unreleased.
Every section has the four headings below, with "None." under any that don't apply.

## Server 0.1.0 - unreleased

### Upgrade order

First public release: install from scratch with `docs/install.md`. Works with agent 0.1.

### Breaking changes

None.

### Security

None.

### Changes

First public release, open source under Apache 2.0.

- The API and web console in one image, `ghcr.io/altiward/altiward-api`, with Postgres for
  storage and an example Docker Compose deployment with Caddy for TLS. Every setting goes
  in `.env`.
- The console: an Overview of who holds admin rights and what needs a look, elevation
  sessions, admins now, the fleet with its integrity checks, enrollment approval, and an
  audit log of console actions. A revoke reaches the Mac within about a second, and the
  console says what the agent did.
- Single sign-on with Entra ID, Okta or another OIDC identity provider, with viewer,
  operator and admin roles from your groups. The console token stays as a break-glass
  login.
- Export to Splunk, Microsoft Sentinel and syslog (CEF or OCSF JSON), console actions
  included. Findings cover admin rights without a grant, rights that outlive their expiry,
  persistence added while someone was admin, new local accounts, failed tamper checks and
  Macs that stop checking in.
- Sentinel setup in one script, `integrations/sentinel/setup.sh`, which can use an Azure
  VM's managed identity. An overview workbook for Sentinel and a dashboard for Splunk come
  in the server bundle.
- `upgrade.sh` upgrades to a new release in one command: it checks the signature, backs up
  the database and waits for the server to report healthy.
- `altiward-api diagnose` prints a report for a bug report, with every secret hidden.
- The console tells admins when a newer server or agent is out. The admin's browser asks
  `api.github.com`; the server contacts nobody. `ALTIWARD_UPDATE_CHECK=false` turns it off.
- `docs/data-handling.md`, for your security review: what Altiward stores, what leaves the
  server and where it goes.

## Agent 0.1.0 - 2026-10-21

### Upgrade order

First public release. Install the server first, then deploy this package and the
`com.altiward.agent` profile through your MDM. For SAP Privileges, add the keys in the
release's `corp.sap.privileges.plist` to your Privileges profile: `PostChangeExecutablePath`
is `/Library/Application Support/Altiward/Altiward.app/Contents/MacOS/Altiward`, and
`PostChangeExecutableChecksum` is the value in that file. Each agent build has its own
checksum, so update it in your Privileges profile before or together with the agent
package, never after. Privileges silently skips a hook whose checksum doesn't match, and
each grant then shows as admin rights "Without a grant" about 30 seconds later; the
agent's `privileges_hook` tamper check reports the mismatch at its next heartbeat.

### Breaking changes

None.

### Security

None.

### Changes

- Works with SAP Privileges: records every grant and revoke Privileges reports, checks
  each against the real `admin` group, and finds admin rights nobody granted. Rights that
  outlive the expiry Privileges set raise an alert, or, with `ExpiryEnforcement` set to
  `enforce`, are removed. The agent never grants admin rights itself.
- Tamper checks, remote revoke from the console, and per-device keys.
- The `privileges_hook` tamper check fails when `PostChangeExecutablePath` isn't
  Altiward's hook, or when `PostChangeExecutableChecksum` doesn't match the installed
  hook, which stops Privileges running it. Like Privileges, the agent compares the
  checksum only when MDM sets both keys.
- The release's `corp.sap.privileges.plist` turns on Privileges' own tamper protection
  (`EnableSystemExtension`). Its system extension also needs approval from your MDM: a
  system extension policy for SAP's team `7R5ZEU67FQ` and Full Disk Access for
  `corp.sap.privileges.extension`, as SAP's `Example_ApprovePrivileges.mobileconfig` does.
- SAP Privileges' settings show "Altiward" next to "Run after privilege change": the hook
  is installed as `Contents/MacOS/Altiward`.
- What changed while someone was admin: new or changed LaunchDaemons and LaunchAgents,
  sudoers rules, SSH keys, local accounts, and Remote Login or Screen Sharing switched on,
  reported on the session as `persistence.detected`. `docs/data-handling.md` lists what
  is sent. A new account says whether it is an admin.
- A tamper check, `privileges_timer`: someone logged in who holds admin rights from SAP
  Privileges stopped Privileges' agent, which runs their timer, so the rights wouldn't
  end. The alert comes at the next heartbeat, before any expiry. To tell, the agent looks
  for that process in the Mac's process list and sends only the answer
  (`docs/data-handling.md`).
- A failing tamper check that stops applying, for example because SAP Privileges was
  removed, closes its alert and says why, so it doesn't stay open in your SIEM.
- A SAP Privileges grant shows the duration the person picked in Privileges, read from
  Privileges' own timer, when no profile fixes it. A managed `ExpirationIntervalMax`
  still caps it, so editing that timer can't put off the overdue alert.
- When an account holding admin rights nobody granted is added to `PermanentAdmins`, the
  agent ends its session at the next heartbeat and leaves the rights alone.
- A revoke that macOS takes a moment to reflect in the `admin` group isn't reported as
  failed: the agent checks again for up to 3 seconds before giving up.
- Console commands arrive within about a second: the agent keeps a request open that the
  server answers as soon as a command is queued. `CommandPollInterval` is only the wait
  after an error, or with a server that can't hold requests.
- A profile installed after the package, as MDMs often send them, or changed later,
  applies within about 15 seconds: the agent restarts itself when its settings change.
- Admin rights nobody granted show in the console within a minute. They are raised after
  30 seconds without a grant, so a Privileges grant whose report is still on its way isn't
  flagged.
- The Installer names the package ("Install Altiward"), shows the Altiward mark under its
  steps in light and dark mode, installs only on the system volume, and refuses macOS
  older than 13.
