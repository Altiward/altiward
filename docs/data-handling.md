# Data handling

What Altiward collects, where it keeps it, and where it sends it, for your security and
privacy review. You run the server ([install guide](install.md)), so all of this stays
on your infrastructure. The Altiward project receives none of it.

## In short

- **Nothing is sent to Altiward.** The agent talks only to your server. The server talks
  only to your database and to the SIEM and identity provider you configure. There is no
  telemetry, crash reporting or registration. Altiward is open source (Apache 2.0) and
  has no licence to check, so nothing in it can stop working over one.
- **The update check runs in the admin's browser, not on the server.** For people with
  the admin role, the console's browser asks `api.github.com` for Altiward's release list:
  at most once a day per admin's browser after a successful check, and at most once an
  hour while GitHub can't be reached. It sends nothing about your fleet: no versions,
  cookies or referrer.
  Like any request a web page makes to another site, it carries the console's address in
  its `Origin` header. The browser compares the versions itself, and the server still
  contacts nobody. `ALTIWARD_UPDATE_CHECK=false` in `.env` turns it off for everyone
  ([In the browser](#in-the-browser)).
- **Maintainers see only what you choose to send:** for example a diagnostics report you
  read first (see [Diagnostics](#diagnostics)).

## What the agent collects on each Mac

The agent records changes to admin rights, not what people do with them.

| What | Detail |
| --- | --- |
| The Mac | Serial number, hardware UUID, macOS version, agent version, SAP Privileges version |
| The person | macOS short name, and their UPN (sign-in name) if you map one in the MDM profile (`UserPrincipalNames`). Altiward doesn't look UPNs up |
| Each elevation | When it started and ended, how long it was allowed for, and the reason they typed (up to 2,048 characters) |
| Who is admin | Every human account in the Mac's `admin` group, checked every 5 minutes, and admin rights that appear without an elevation |
| Health | Whether the agent, SAP Privileges and their settings are intact, and how many events are waiting to send. While someone holds rights from SAP Privileges, this includes whether Privileges' timer is still running for them: the agent looks for its process in the Mac's process list and sends only the answer |
| Revokes | The results of revokes sent from the console |
| What changed while someone was admin | New or changed LaunchDaemons and LaunchAgents (their path, label, program and arguments), new sudoers rules, new SSH keys allowed to log in (their type and fingerprint, never the key), new local accounts (name, ID and whether it is an admin), and Remote Login or Screen Sharing switched on. Only changes made while an elevation was open are sent; the Mac keeps the last snapshot in the agent's own folder |

The agent does **not** collect the Mac's name, IP address, process or command
history, the contents of people's files, browsing, keystrokes or location. (Your server sees the address each
connection comes from, as any web server does.)

The event format is published in full in `docs/schema/event.schema.json` in the source
repository, and Altiward can send it to you. The server rejects any field it doesn't
define.

## Connections

### From the Mac

The agent connects only to the server address in your MDM profile (`ServerURL`), over
HTTPS. It contains no third-party code, and makes no connections to Apple, SAP, Altiward
or anyone else. It:

- enrolls once with the enrollment token from your profile, registering a key it makes
  on the Mac;
- sends events as they happen, and a health event every 5 minutes;
- keeps a request open for commands (such as a revoke), which your server holds for up to
  50 seconds and answers when one is queued, then asks again; after an error it waits 60
  seconds (`CommandPollInterval`). It reports each command's result.

Use an `https://` address: the agent doesn't refuse a plain `http://` one.

### From the server

Each connection exists only if you configure it.

| To | Why | Setting |
| --- | --- | --- |
| Your Postgres | Storage | `ALTIWARD_DATABASE_URL` |
| Splunk HTTP Event Collector | SIEM export | `ALTIWARD_SPLUNK_*` |
| Microsoft Entra ID (or, with a managed identity, the Azure VM's metadata service at 169.254.169.254, or the container app's identity endpoint) and your Azure Monitor endpoint | Sentinel export | `ALTIWARD_SENTINEL_*` |
| Your syslog receiver, over TLS 1.2 or later by default | SIEM export | `ALTIWARD_SYSLOG_*` |
| Your identity provider | Console sign-in | `ALTIWARD_OIDC_*` |

**What your SIEM receives:** each event as an OCSF record, with the Mac's serial and
macOS version, the person's short name and UPN, the reason they typed, and the event's
details. Console actions go there too, naming the person who made them.

In the example deployment, Caddy also asks Let's Encrypt for TLS certificates unless you
provide your own. If you pull the image from the registry instead of loading the file,
Docker connects to `ghcr.io`.

### In the browser

The console loads everything from your server: no fonts, scripts or analytics from
anywhere else. Its content security policy allows only its own origin, and, while the
update check is on, requests to `https://api.github.com`.

**The update check.** When someone with the admin role opens Overview or Settings, their
browser asks GitHub's public API for the release list
(`GET https://api.github.com/repos/Altiward/altiward/releases`): at most once a day per
admin's browser after a successful check, and at most once an hour while GitHub can't be
reached. The answer is kept in that browser's local storage for 24 hours, or in memory
for the tab if local storage is blocked. The request carries no
cookies, no referrer and no versions, so it says nothing about your fleet. GitHub sees
what any website sees of a request from a browser: its IP address and user agent, and,
in the `Origin` header browsers add to every request to another site, the console's
address (such as `https://altiward.example.com`). The browser compares the versions
itself and shows a notice when a newer server or agent is out. Viewers and operators
never make the request. To turn it off for everyone, set
`ALTIWARD_UPDATE_CHECK=false` in `.env` and run `docker compose up -d`: the console then
asks nobody, and its content security policy no longer allows `api.github.com`.

**Appearance.** The theme and light or dark someone picks in Settings stay in their
browser's local storage. They never reach the server.

## What the server stores

Everything is in your Postgres database.

| Data | Kept |
| --- | --- |
| Every event from every Mac, in full | Forever, for now |
| Elevation sessions, including the person's UPN and reason | Forever, for now |
| Each Mac's latest state: versions, admins, health | Forever, replaced as it changes |
| Each Mac's enrollment: serial, hardware UUID and **public** key | Forever; revoking stops the Mac reporting |
| Commands sent from the console, who sent them, and their results | Forever |
| Activity: every change made in the console, and every sign-in | Forever by default; or from 365 days, with `ALTIWARD_AUDIT_RETENTION_DAYS` |
| Console sign-in sessions: the person's email, name, identity-provider ID and role | 12 hours at most, 1 hour idle; removed on sign-out, or when an admin ends it |
| Events waiting for each SIEM | Until the SIEM accepts them |
| When each SIEM last accepted something | Replaced at each delivery |
| When the server was set up | Forever |

Activity entries can't be edited, and a database rule allows deleting only entries more
than 365 days old. Entries your SIEM hasn't received yet are never removed. Your
identity-provider groups aren't stored, only the role they map to.

Back up and protect the database as you would any system holding staff names and
security records ([Backups](install.md#backups)).

## Secrets and keys

- **Mac keys.** Each Mac makes its own key pair when it enrolls. The private key stays
  on the Mac; the server stores only the public key. Every request after enrollment is
  signed with it, and the server refuses requests more than 5 minutes old or from a
  revoked Mac.
- **Where the Mac's key lives.** In a file under `/Library/Application Support/Altiward/`
  that only root can read. That protects it from standard users but not from someone
  with admin rights on that Mac. Moving it into the Keychain or Secure Enclave is planned.
- **The enrollment token** lets a Mac enroll, and does nothing else. It is in the MDM
  profile, so anyone on a Mac can read it. A new enrollment shows in **Enrollments**, where
  an admin can revoke it, and with **Approve Macs that enroll again** on, a Mac that
  returns with a new key waits for approval. Changing the token doesn't affect Macs
  already enrolled.
- **Console and agent tokens** are kept in the server's `.env` file (keep it `chmod 600`).
  The server holds only their SHA-256 digests in memory and records each by a fingerprint,
  never the token.
- **Console sessions** are an HttpOnly cookie, Secure and `__Host-` prefixed over HTTPS,
  with SameSite=Lax and a CSRF token on every change. The database stores a hash of
  the session ID, not the ID itself.

## On the Mac

The agent keeps one database, `/Library/Application Support/Altiward/agent.sqlite`,
readable only by root. It holds events waiting to send (removed once your server
confirms them), the elevations open now, the Mac's key, and revoke results (removed 30
days after they are reported). It logs to the Mac's unified log under
`com.altiward.agent`.

## Network and transport

- **TLS** is handled in front of the server: by Caddy in the example deployment, or by
  your load balancer. The server itself listens on plain HTTP inside the deployment.
- **Two hostnames.** Only the agent endpoints face the internet. The console hostname
  accepts only the networks you list in `ALTIWARD_CONSOLE_ALLOW`.
- **The database connection** in the example deployment stays on Docker's internal
  network without TLS. With your own Postgres, use `sslmode=require` or stronger
  ([An existing Postgres](install.md#an-existing-postgres)).

## Diagnostics

`altiward-api diagnose` prints a JSON report to attach to a bug report. It contains the
version, which settings are set, migration state, record counts, each SIEM's backlog and
last error, whether each SIEM and the identity provider accept a connection (and the
Azure VM's metadata service or the container app's identity endpoint, when Sentinel uses a
managed identity), and when the server was set up.

It hides every secret: tokens, client secrets, the database password. It holds no event
contents, names or reasons, only counts. It sends nothing: you read it, then decide
whether to send it.

## Releases

Every release is signed by the release workflow in the Altiward repository on GitHub, so
you can check that the files came from there unchanged ([Checking a release](install.md#checking-a-release)). The
Mac package is also signed with Apple's Developer ID and notarized. Each release lists
its open-source components and their licences in `THIRD_PARTY_NOTICES.md`.

When anything on this page changes, the release notes say so.
