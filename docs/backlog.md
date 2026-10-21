# Development backlog

Engineering work that is known but not scheduled, with what each item is waiting on. The
README's [Status](../README.md#status) gives the summary; this file has the detail.

You host your own server, so
there is no tenant provisioning, per-tenant configuration or data-region work here.

Each item says what blocks it:

- **Decision:** needs a product or design choice before building.
- **Account:** needs a vendor account or tenant to build against or test.
- **Hardware:** needs a Mac set up in a particular way.
- **Ready:** can be built now.

## Self-hosted release

What anyone needs to run their own server.

### Install guide and example deployment files

**Done:** [docs/install.md](install.md) and [deploy/compose](../deploy/compose/), with
two install sizes (the bundle, or your own Postgres and load balancer),
and [docs/data-handling.md](data-handling.md) for security reviews. Both ship in
the release bundle. Still open: Kubernetes manifests or a Helm chart, when someone
asks.

### Upgrades

**Done:** `deploy/compose/upgrade.sh` upgrades from the release files in one command
(install guide, "Releases and updates"), and `make test-upgrade`, in CI, installs a
release in Docker and upgrades it through the cases an admin meets. Not yet run against
a real signed release, so the cosign check waits for the first `server-v` tag.

### Public source and releases

**Done in the repository:** Apache 2.0, with no licence enforcement,
and release notes in `CHANGELOG.md`. **Still open:** the first public tag. Trademark
clearance on the name "Altiward" comes first. Then:
make the repository and the `ghcr.io` package public, and publish each release's files on
GitHub Releases ([releasing](releasing.md)).

### Diagnostics command

**Done:** `altiward-api diagnose` prints a JSON report with secrets hidden: the version,
settings, token fingerprints, migration state, counts, export backlog per sink and
whether each SIEM endpoint accepts a connection, with a plain-words `problems` list. It
connects without migrating and sends nothing. `altiward-api health` backs the image's
health check. Logs stay separate (`docker compose logs`).

Export outbox rows for a sink removed from the configuration stay until the operator runs
`altiward-api drop-exports SINK`, which diagnostics suggests. It is a command rather than
a cleanup on start, so a mistyped setting can't silently throw away a SIEM's backlog.

### Signed image releases

**Done:** pushing a `server-vX.Y.Z` tag runs `.github/workflows/release-server.yml`: the
image for amd64 and arm64 with provenance and an SBOM, pushed to
`ghcr.io/<owner>/altiward-api:<version>`, signed keyless with cosign and checked, plus the
deployment bundle from `scripts/server-bundle.sh`. CI builds the image, checks it reports
healthy and builds the bundle on every change. Not yet run for real: it needs the first
tag.

Distribution is decided: releases are public, on GitHub
Releases ([docs/releasing.md](releasing.md)).
Each server release also carries the image saved per platform for `docker load`, the
release notes from `CHANGELOG.md` (the workflows refuse a version without a dated entry)
and `SHA256SUMS` signed keyless; agent releases carry notes and signed checksums too.

### Upgrade and compatibility rules

**Done:** `TestPostgresUpgradesFromEveryMigration` builds a database at every point in the
migration history, with data in the old format, then upgrades it and reads and writes
through today's code. `TestOlderAgentsStillReport` posts the frozen events of each
supported agent release (`docs/schema/compat/`, starting with agent 0.1) and requires
them all to be accepted. AGENTS.md has the rules.

Release notes now come from `CHANGELOG.md` with an "Upgrade order" heading in every
entry. `GET /v1/about` gives the console the server's version and
`OldestSupportedAgent`; the sidebar shows the version and Fleet tags older agents
**Agent outdated**.

## Console

### Overview dashboard

**Done** (2026-10-18): the console's first page, from `GET /v1/overview?days=7|30|90`.
`backend/internal/report` works it out from the reducers' session and device state and
each SIEM's queue, as a pure function that detection rules or an evidence export could
reuse later: admins now by source, rights past expiry, Macs failing a check or silent,
elevations per day (per week over 30 days), median time held against allowed and the
share given back early, the top five people and Macs, agent versions and each SIEM's
state. Tiles link to Admins now, Sessions (`?q=`), Fleet (`?q=`, `?show=attention`,
`silent` or `outdated`) and Settings, and terms have help tags (`Explain`). Charts are
drawn with CSS in the brand tokens, with a table for screen readers; no chart library.

Still open, if users ask: a comparison with the period before, and a CSV of the
figures.

### SSO with roles

**Done:** OIDC code flow with PKCE through
go-oidc, one identity provider per deployment from `ALTIWARD_OIDC_*`, viewer, operator
and admin roles from a groups claim, server-side sessions in an HttpOnly cookie with a
CSRF token, and console tokens kept as admin break-glass logins audited as
`break-glass:<fingerprint>`. Audit entries and commands name the person; `sign_in` and
`sign_out` are audited and exported as OCSF Authentication. Tested against a fake
identity provider (`backend/internal/sso/ssotest`).

**Done since:**

- **Real Entra ID tenant:** a test server has signed in through Entra with the three groups since
  2026-10-17. Groups overage (`_claim_names`) refuses sign-in with a clear message rather
  than guessing a role. App roles (`Altiward.Admin`, `.Operator`, `.Viewer`) are set up
  in the test Entra app and documented in the install guide, step 5.
- **Who is signed in:** Settings lists console sign-ins for admins, and an admin can end
  one (`end_console_session`, audited and exported).

**Still open:**

- **Account:** sign in with app roles on a test server (`ALTIWARD_OIDC_GROUPS_CLAIM=roles` and
  the role values in `.env`; needs someone assigned a role to sign in), and against an Okta
  org.
- Signing out of the identity provider as well (RP-initiated logout), if users want it.

### Audit log follow-ups

**Done.**

- **SIEM export.** Done: console actions share each sink's export queue (an outbox row
  holds an event or an audit entry) and map to OCSF API Activity. The agent event schema
  is unchanged.
- **Retention.** Done: `ALTIWARD_AUDIT_RETENTION_DAYS` (at least 365, unset keeps
  forever) purges daily. The trigger allows deleting only entries over 365 days old by the
  database's clock, and the purge skips entries still waiting for export.

### Permanent admins on each Mac

**Ready.** Each heartbeat already reports the Mac's `permanent_admins`, and the console's
types include it, but the Fleet inspector doesn't show it. List them there, read-only,
saying they come from the Mac's configuration profile, so an operator can see why an
account with admin rights isn't in Admins now.

They stay set in the MDM, not the console. The managed profile holds the settings the
agent trusts, and it flags settings made any other way as tampering. A console setting
would let a console operator, or anyone who took over the server, exempt an account from
revokes. The MDM also names the LAPS account, so the same place lists it.

### Point an unexplained admin at PermanentAdmins

**Ready.** When the console shows an admin nobody granted, add a line saying that if this
is the Mac's managed admin account (LAPS) or another standing IT account, it belongs in
`PermanentAdmins` in the Altiward profile, with a link to the install guide's step.
Altiward can't tell a managed account from one an admin made to look like one, so the
console explains and the MDM decides.

## Agent

### Platform SSO identity mapping

**Blocked on:** account and hardware (a Mac registered with Platform SSO against Entra
ID or Okta).

The UPN for each local user comes only from the `UserPrincipalNames` preference today.
With Platform SSO, the agent could read the identity-provider account linked to each
local user instead. Apple has no documented API for this, so the first step is finding
out, on a registered Mac, where the link is stored (the user's directory record,
`app-sso platform -s`, or a keychain item) and whether a root daemon can read it.

Done when: on a Platform SSO Mac, events carry the user's UPN with no
`UserPrincipalNames` entry, and that preference still wins when set.

### A schema version for the agent's store

**Ready,** and needed by the first agent release that changes the store.

The agent's SQLite store (`AgentStore.swift`) has no schema-version marker: 0.1.0 creates
its tables and nothing records which layout they have. The first release that adds a
column or table must introduce one (for example `PRAGMA user_version`, treating 0 as the
0.1.0 layout) and upgrade a 0.1.0 store from it, so later releases know what they're
opening.

### End an out-of-band session when a grant replaces it

**Ready.**

When a Privileges grant arrives for a user who already has an open out-of-band session
(admin rights nobody granted), `record()` in `ElevationTracker.swift` replaces that
user's ledger row with the new Privileges session but sends nothing to end the
out-of-band one. The server's "Without a grant" session then stays open, and its
`admin.out_of_band` finding in the SIEM never closes. The fix: in the same transaction,
send an inferred `elevation.revoked` for the replaced session before the grant, and map
it to an OCSF Close the way the `permanent_admin` end is mapped, since the rights are now
granted rather than gone.

### Close tamper alerts for checks that stop applying

**Done** (2026-10-18): a failing check that stops applying sends `agent.tamper` with
state `retired` and the reason in `problem`. The SIEM gets an OCSF Close with status
Other ("No longer checked"), and the console says "No longer checked".

### Record use of permanent admin accounts

**Blocked on:** decision (what counts as use, and the event's shape).

Accounts in `PermanentAdmins`, such as the local admin account an MDM manages with LAPS,
are left out of tracking, so Altiward records nothing when someone uses one. The MDM
shows who looked up the password; nothing shows what happened on the Mac. Record each use
as evidence, without an out-of-band alert:

- **Sign-ins:** a permanent admin account becoming the console user, and SSH or
  screen-sharing sign-ins.
- **Credentials typed into a prompt:** the common LAPS case is a technician entering the
  account's name and password into an admin prompt while a standard user is signed in.
  Record which account approved it, on whose session.
- **`sudo` by that account.**

Each use becomes one event with a start and an end where there is one, for the console and
the SIEM, where it joins the MDM's record of the password lookup. Without the Endpoint
Security entitlement the sources are the console user and the unified log, which is
corroboration, not evidence, because an admin can erase it. With it:
`NOTIFY_LW_SESSION_LOGIN`, `NOTIFY_OPENSSH_LOGIN`, `NOTIFY_SUDO` and
`NOTIFY_AUTHORIZATION_JUDGEMENT`. A new event type changes the schema, both decoders and
the fixtures together, the server ships first, and `docs/data-handling.md` gains a line.

### Persistence detection and remediation

**Detection done:** `persistence.detected`
([schema](schema/README.md#persistencedetected-findings)). The daemon snapshots launch
items, sudoers, SSH keys, local accounts and remote access after each grant and end and
on each heartbeat, and reports changes on the sessions open in between. Places it can't read show
in the fleet view's integrity section, and tag the Mac "Partly checked". Still open:

- **Hardware:** check on a real Mac, without a PPPC profile, that the root daemon reads
  `~/.ssh/authorized_keys` and `~/Library/LaunchAgents`. Privacy protection isn't
  expected to cover them, but `agent.health` reports `persistence_unreadable` if it does.
  If it does, ship a PPPC profile granting the daemon Full Disk Access.
- **More places,** if users ask: login items (Background Task Management), cron,
  configuration profiles, authorization plugins, PAM.
- **Remediation** (undoing what it finds), **blocked on:** decision (which changes it may
  undo, and when).

## Integrations

### Jamf Pro and Intune

**Blocked on:** account (a Jamf Pro instance and an Intune tenant).

Push the `com.altiward.agent` and Privileges profiles, and read device groups to target
them. Which comes first is still open.

### LAPS accounts from the MDM

**Blocked on:** Jamf Pro and Intune (above), and the same Jamf Pro instance and Intune
tenant.

Read from Jamf Pro or Intune which local admin account each manages with LAPS, and flag
Macs where that account isn't in `PermanentAdmins`, for example "Jamf manages `itadmin`
with LAPS, but it isn't a permanent admin on 40 Macs". Read-only: the MDM's profile stays
the only place that exempts an account, and Altiward checks that the two agree.

### Removal alerts from the MDM's check-in

**Blocked on:** account (the same Jamf Pro instance and Intune tenant as Jamf Pro and
Intune, above).

Read each Mac's last MDM check-in and alert when the MDM still hears from a Mac that
Altiward doesn't: the agent has almost certainly been removed. That can fire within hours,
not after `agent.silent`'s 72, and keeps closed laptops quiet. The alert names who was
admin when the agent went silent. Add a reinstall policy to the install guide too (a Jamf
smart group, Intune's install check), tested on both.

### EDR session queries

**Blocked on:** account (a Sentinel workspace with Defender for Endpoint, a Splunk with
CrowdStrike Falcon data).

The site's EDR records what ran; Altiward's sessions say which slice matters, and the
two meet in the SIEM. Ship, in [altiward-siem](https://github.com/Altiward/altiward-siem), for each pair:

- a hunting query: an Altiward session's start and end (`metadata.correlation_uid` ties
  them), then the EDR's process and file events for that Mac and user in between
- a detection: persistence written during an elevation window

Joins use `device.hw_info.serial_number` and `user.name`, or `user.email_addr` when the UPN
is known. If an EDR can only match on hostname, add a hostname to the event (contract
change, plus [data-handling.md](data-handling.md)). Later, for sites without a SIEM,
the console could pull the same events through the EDR's API.

### Entra ID and Okta

**Blocked on:** account (an Entra tenant and an Okta org).

User identity from the identity provider, for example each person's UPN without a
`UserPrincipalNames` entry in the profile. This shares app registrations with console
SSO, so build them together.

### Syslog follow-ups

**Blocked on:** ready.

- The syslog sink opens one connection per batch. That is fine at today's volume; keep a
  connection open if a receiver complains about connection churn.
- No CEF content pack yet (QRadar DSM, ArcSight parser). The fields and starter rules are
  in [integrations/syslog](../integrations/syslog/README.md). **Blocked on:** account: a
  parser can only be tested in QRadar or ArcSight, so wait for a user who runs one.

### Sentinel setup in one step

**Done:** `deploy/sentinel/setup.sh` creates the table, a rule with its own ingestion
URL (`"kind": "Direct"`, a separate endpoint only with `--private-link`) and the app, or
with `--vm` the VM's managed identity, and prints the `.env` lines. Its tests run it
against a fake `az`. Run on a test server on 2026-10-18 with `--vm`, against a new workspace: it
created the table (so its "not found" check matched Azure's real error), the rule came
back with its own URL, and 417 replayed events and console actions arrived. A new
subscription also needed `Microsoft.SecurityInsights` and `Microsoft.OperationsManagement`
registered before Sentinel could be turned on; the guide now says so.

### SIEM status and test in the console

**Done:** Settings shows each sink's queue and last error, with *Send test event* and
*Retry now* for admins (`console.test_export`, `console.retry_exports`), and when each
sink last delivered something for the tenant (`export_deliveries`, 2026-10-18).

### Managed identity for Sentinel

**Done:** `ALTIWARD_SENTINEL_AUTH=managed-identity` takes the token from the VM's IMDS,
and a test server has exported this way since 2026-10-18, with no secret. Still open: a
certificate credential for servers outside Azure.

### Replay events to a new SIEM

**Done:** `altiward-api replay-exports <sink> <since>`.

### Sentinel solution with a push connector

**Blocked on:** decision (whether to list in Content Hub, which needs a Partner Center
account).

A Codeless Connector Framework push connector creates the table, rule, app and role from
Sentinel's Data connectors page and shows the values to copy, as Jamf Protect does. It
is in preview. It can ship privately as a Deploy to Azure template before any listing.

### SIEM dashboards

**Done for Sentinel** (2026-10-18): `integrations/sentinel/workbook.json`, and
`workbook.arm.json` to deploy it, with the console overview's figures rebuilt from the
OCSF records (sessions from `correlation_uid`, source and expiry from
`unmapped.altiward`). Every query ran against a test workspace, and the template is
deployed there. A test keeps the template in step with the workbook (`-update` rewrites
it). The workbook goes into the Sentinel solution above when that ships.

Still open:

- **Splunk dashboard. Done** (2026-10-18): `integrations/splunk/altiward_overview.xml`, a
  classic (Simple XML) dashboard. Every panel's search ran against a local Splunk 9.4
  trial container, fed by the real HEC export and a test workspace's Sentinel history, and it was
  installed with the REST commands in the README. A test checks every search reads
  `altiward:ocsf` from the chosen index.
- Once the EDR session queries exist, a panel for what ran during each elevation window,
  which the console can't show.

### SIEM settings in the console

**Blocked on:** decision (it reverses the rule that SIEM sinks are set per deployment,
in the server's environment).

Not worth it yet: with the items above done, the step left is pasting a few lines into
`.env`. It would need sinks that change at runtime (the outbox queues each event
for the sinks configured when it's written), secrets stored encrypted in the database (no
key exists today), and an update to [data-handling.md](data-handling.md).

## Backend and hosting

### Demo data for silent Macs

**Blocked on:** ready, low priority. `make console-seed` says it seeds one silent Mac, but
since check-ins are timed by the server's clock, a Mac it posts as last
heard four days ago counts as checking in now, so no `agent.silent` is raised. The seed
needs another way to make one, such as a store-level helper for development.

### Silent Mac alert follow-ups

**Done:** an admin can turn the alert off in Settings (`silent_alerts_off`, 2026-10-18).
A Mac already reported silent still sends `resumed` when it checks in.

### Several organisations on one server

**Blocked on:** demand, for example from an MSP that wants to run one server for its
clients.

The data model keeps `tenant_id` everywhere, so one server can serve several tenants.
Serving several organisations would add tenant provisioning, per-tenant SIEM sinks and
SSO, and data regions.
