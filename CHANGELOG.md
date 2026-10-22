# Changelog

Release notes for the Altiward server and the Mac agent, newest first. Releases are
published on GitHub, and each release's section
is its notes.

Each release has one section headed `## Server X.Y.Z - YYYY-MM-DD` or
`## Agent X.Y.Z - YYYY-MM-DD`. Write `unreleased` instead of the date until the day it
ships: the release workflows refuse a version whose section is missing or unreleased.
Every section has the four headings below, with "None." under any that don't apply.

## Agent 0.1.1 - unreleased

### Upgrade order

Upgrade the server to 0.2.0 first. An older server ends the replaced session as `revoked`
and doesn't close its finding.

### Breaking changes

None.

### Security

None.

### Changes

- The agent's store records its schema version, and upgrades a 0.1.0 store in place
  with its data. An older agent can't open a store written by a newer one: reinstall the
  newer release instead of downgrading.
- A Privileges grant for a user who holds admin rights nobody granted now ends that
  "Without a grant" session, with trigger `privileges_grant`, before it starts the
  Privileges one. The grant carries `replaced_out_of_band: true`. Before, the session stayed
  open and its `admin.out_of_band` finding never closed.

## Server 0.2.0 - unreleased

### Upgrade order

None.

### Breaking changes

None.

### Security

None.

### Changes

- A Mac's details in Fleet list its permanent admins, read-only, from its configuration
  profile, and say whether each one is an admin now.
- Admin rights without a grant say that a managed admin account (LAPS) or another
  standing IT account belongs in `PermanentAdmins` in the Altiward profile, with a link
  to the install guide.
- A "Without a grant" session that a Privileges grant replaces ends with the reason
  `privileges_grant` ("Replaced by a Privileges grant" in the console), and the session
  that grant starts is flagged `after_out_of_band`. The SIEM export closes its
  `admin.out_of_band` finding with status Other, "Replaced by a Privileges grant", not
  Resolved, since the grant is reported by Privileges' hook. Needs agent 0.1.1.
- The Sentinel export can sign in with a certificate on the app instead of a client
  secret, for servers outside Azure: `ALTIWARD_SENTINEL_AUTH=certificate` and
  `ALTIWARD_SENTINEL_CERTIFICATE_FILE`, a PEM file in `certs/`
  (`integrations/sentinel/README.md`).

## Server 0.1.1 - 2026-10-21

### Upgrade order

None.

### Breaking changes

None.

### Security

- The console moves to React Router 7.18.4, which fixes an open redirect through a
  backslash in links (GHSA-wrjc-x8rr-h8h6) and a constructor injection in server-side
  rendering, which the console doesn't use (GHSA-337j-9hxr-rhxg).
- The server is built with Go 1.27.3. Go 1.25, which built 0.1.0, no longer gets security
  fixes.

### Changes

- The console runs on React 19 and React Router 7, and builds with Vite 8 and
  TypeScript 7. It looks and works as before.

## Server 0.1.0 - 2026-10-21

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
`com.altiward.agent` profile through your MDM. Add the keys in the release's
`corp.sap.privileges.plist` to your SAP Privileges profile. `PostChangeExecutableChecksum`
differs for each agent build, so update it before or together with the agent package, never
after: Privileges silently skips a hook whose checksum doesn't match.

### Breaking changes

None.

### Security

None.

### Changes

First public release, open source under Apache 2.0.

- Works with SAP Privileges: records every grant and revoke Privileges reports, checks
  each against the real `admin` group, and finds admin rights nobody granted. Rights that
  outlive their expiry raise an alert, or, with `ExpiryEnforcement` set to `enforce`, are
  removed. The agent never grants admin rights itself.
- Tamper checks, including that Privileges runs Altiward's hook with a matching checksum
  and that nobody stopped Privileges' timer. A check that stops applying closes its alert
  and says why.
- Reports what changed while someone was admin: LaunchDaemons and LaunchAgents, sudoers
  rules, SSH keys, local accounts, and Remote Login or Screen Sharing switched on.
  `docs/data-handling.md` lists what is sent.
- Remote revoke from the console, which reaches the Mac within about a second, and
  per-device keys.
- Settings come from an MDM profile and apply within about 15 seconds, even when the
  profile arrives after the package.
- The release's `corp.sap.privileges.plist` turns on Privileges' own tamper protection,
  whose system extension also needs approval from your MDM (`docs/install.md`).
- A signed and notarized installer package for macOS 13 or later.
