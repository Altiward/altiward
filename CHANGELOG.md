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

- Altiward is open source under Apache 2.0. Releases are public on GitHub, and the
  image is public at `ghcr.io/altiward/altiward-api`, pulled without a login.
- The API and web console in one image, with Postgres for storage and an example Docker
  Compose deployment with Caddy for TLS.
- Elevation sessions, admins now, fleet inventory with integrity checks, remote revoke,
  enrollment approval, and an audit log of console actions.
- Alerts for Macs that stop checking in, timed by the server's clock so a Mac whose clock
  is wrong can't cause or hide one.
- Export to Splunk, Microsoft Sentinel and syslog (CEF or OCSF JSON). On an Azure VM, the
  Sentinel export can sign in with the VM's managed identity
  (`ALTIWARD_SENTINEL_AUTH=managed-identity`), so there is no client secret to store or
  renew. A SIEM or identity provider with an internal CA's certificate works once
  `ALTIWARD_TRUSTED_CAS_FILE` names that CA.
- Sentinel setup is one script: `integrations/sentinel/setup.sh` in the server bundle
  creates the table, a rule with its own ingestion URL (no separate endpoint, except with
  private link) and the app, or with `--vm` the VM's managed identity, then prints the
  lines for `.env`.
- A session's timeline lists the persistence the agent found while it was open, and the
  SIEM gets it as a Persistence finding whose evidence names each file. A new local
  account is a finding of its own, "Admin account created" (High) or "Local account
  created" (`altiward.account_created`, MITRE T1136.001), naming the account and who was
  admin when it appeared. The fleet view tags a Mac "Partly checked" when its agent can't
  read some of the places it looks.
- `altiward-api diagnose` prints a report for a bug report, with every secret hidden.
- `altiward-api drop-exports` clears the queue of a SIEM you no longer send to, and
  `altiward-api replay-exports` sends a newly connected SIEM what came before it.
- The console's Settings shows each SIEM's queue and last error, and lets an admin send a
  test event or retry failed exports now. Both are console actions, in Activity and your
  SIEM as `console.test_export` and `console.retry_exports`.
- Console actions (revokes, enrollment approvals, settings changes) go to your SIEM too,
  as OCSF API Activity.
- Single sign-on to the console with Entra ID, Okta or another OIDC identity provider,
  with viewer, operator and admin roles from your groups. Activity and your SIEM name
  each person, including when they sign in and out. The console token stays as a
  break-glass login, recorded as such.
- `ALTIWARD_AUDIT_RETENTION_DAYS` removes console activity older than a period you choose,
  at least a year. By default it is kept forever.
- The console tells admins when a newer server or agent is out, on Overview and in
  Settings, with whether it fixes a security problem and the `upgrade.sh` command for it.
  It only tells; nothing upgrades itself. The admin's browser asks `api.github.com` for
  the release list, sending nothing about your fleet: at most once a day per admin's
  browser after a successful check, and at most once an hour while GitHub can't be
  reached. The server still contacts nobody. `ALTIWARD_UPDATE_CHECK=false` turns it off
  (`docs/data-handling.md`).
- `upgrade.sh` in the deployment files upgrades to a new release in one command: it
  checks the files and their signature, backs up the database, keeps deployment files you
  changed, restarts and waits for the server to report healthy. It also installs release
  candidates (`0.1.1-rc.1`), which the release then replaces.
- Every setting, including single sign-on and all three SIEMs, goes in `.env`, so
  there's no need to edit `compose.yaml`. CA files and your own certificates go in
  `certs/`.
- `docs/data-handling.md` in the bundle, for your security review: what Altiward stores,
  what leaves the server and where it goes. The server stores when it was set up and
  nothing else about itself. The install guide compares running the bundle with using
  your own database and load balancer.
- After a revoke, the console waits for the Mac and says what it did: rights removed,
  nothing to remove, or why it couldn't. A permanent admin's session offers no revoke,
  and the API refuses one (`409`), since the agent never removes their rights.
- A revoke reaches the Mac within about a second: the server holds each Mac's request for
  commands until one is queued, for up to 50 seconds. Behind
  your own load balancer, allow at least 60 seconds of idle time on the agent listener.
- When an account holding admin rights without a grant is made a permanent admin, its
  session ends as "Now a permanent admin", and the SIEM finding closes as resolved under
  the same `finding_info.uid`, the session's ID.
- Rights that outlive their expiry raise the "Admin rights outlived their expiry" finding
  in your SIEM even when the agent removed them (`ExpiryEnforcement` set to `enforce`), as
  well as the revoke record. They usually mean SAP Privileges' timer was stopped.
- Settings lists who is signed in to the console, for admins, and an admin can end
  someone's sign-in, for example after a role change at your identity provider. Ending one
  is audited, and goes to your SIEM as `console.end_console_session`.
- Settings shows when each SIEM last accepted something, and an admin can turn off the
  alert for Macs that stop checking in (`silent_alerts_off`). With it off, a Mac already
  reported still sends its resolved alert when it checks in again.
- The install guide shows how to sign in with Entra ID app roles instead of groups, so
  people in many groups never hit Entra's groups limit (step 5).
- The fleet view's integrity section gives each failing check the severity your SIEM
  receives for it, and shows each recent alert's problem in full on a line of its own.
- The console opens on an Overview: who holds admin rights now by source, what needs a
  look (rights past their expiry, Macs failing a check or not checking in), elevations
  over the last 7, 30 or 90 days, time held against time allowed, the people and Macs
  that elevate most, agent versions and whether each SIEM is keeping up. Each tile links
  to the list behind it, and terms explain themselves when you hover over or tab to them.
- The console calls admin rights that nobody granted through Privileges "Without a
  grant", the same words as the SIEM finding.
- The console follows brand v4: neutral greys and ink (Mono) with colour only for state,
  verified in blue, set in Inter and JetBrains Mono. Other themes are Slate (cool greys
  and blue), Moss (sage and forest green) and Paper (warm paper and orange), each light or
  dark. Choose one, and light, dark or the system's, under Appearance in Settings; the
  choice is kept in that browser.
- An Altiward overview dashboard for Splunk, `integrations/splunk/altiward_overview.xml`
  in the server bundle: paste it into a classic dashboard, or install it with one REST
  call. It shows the console Overview's figures from your `altiward:ocsf` events.
- An Altiward overview workbook for Microsoft Sentinel, in the server bundle as
  `integrations/sentinel/workbook.arm.json` (install or update it with one
  `az deployment group create`) and `workbook.json` (paste it into Sentinel's Advanced
  editor). It shows the console Overview's figures from the events in your workspace.
- A tamper alert closes as "No longer checked" (OCSF Close, status Other) when its check
  stops applying on the Mac, with the reason in `status_detail`; the console shows the
  same words.
- The example `corp.sap.privileges.plist` turns on Privileges' own tamper protection
  (`EnableSystemExtension`), which Altiward reports as a High finding while it's off. The
  install guide says what else it needs from your MDM.
- Session states, flags, sources and the fleet view's integrity checks explain themselves:
  hover over them in a list, or hover or tab to them in a session's or Mac's details.

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
