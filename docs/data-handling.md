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
  hour while GitHub can't be reached or the list doesn't include the running server's
  version yet. An admin's **Check now** in Settings › Updates asks again, at most once a minute.
  It sends nothing about your fleet: no versions, cookies or referrer.
  Like any request a web page makes to another site, it carries the console's address in
  its `Origin` header. The browser compares the versions itself, and the server still
  contacts nobody. `ALTIWARD_UPDATE_CHECK=false` in `.env` turns it off for everyone
  ([In the browser](#in-the-browser)).
- **Maintainers see only what you choose to send:** for example a diagnostics report you
  read first (see [Diagnostics](#diagnostics)).

## What the agent collects on each Mac

The agent records changes to admin rights and each use of a permanent admin account, not
what people do with them otherwise.

| What | Detail |
| --- | --- |
| The Mac | Serial number, hardware UUID, macOS version, agent version, SAP Privileges version |
| The person | macOS short name, and their UPN (sign-in name) if you map one in the MDM profile (`UserPrincipalNames`). Altiward doesn't look UPNs up |
| Each elevation | When it started and ended, how long it was allowed for, and the reason they typed (up to 2,048 characters) |
| Who is admin | Every human account in the Mac's `admin` group (any member with a UID of 500 or more, and any other direct member apart from `root` and `_` accounts, hidden ones included), checked every 5 minutes, and admin rights that appear without an elevation |
| Health | Whether the agent, SAP Privileges and their settings are intact (including Privileges' daily admin budget, if set), and how many events are waiting to send. The Privileges settings include whether MDM caps how long a grant lasts and turns renewals off, whether apps are set to renew rights automatically (yes or no, not which), whether Privileges runs the hook on give-backs, and whether it revokes rights at sign-in or after a clock change, with the account names its profile excludes from each. While someone holds rights from SAP Privileges, this includes whether Privileges' timer is still running for them: the agent looks for its process in the Mac's process list and sends only the answer |
| Revokes | The results of revokes sent from the console, and, when `OutOfBandEnforcement` is `enforce`, each admin nobody granted that the agent removed |
| From SAP Privileges' system extension | Only with Privileges 2.6 or later and its system extension on. For admin rights nobody granted, the process that added the account to `admin`; for each attempt the extension blocked on Privileges, the item and the process that tried. For each process: its path, signing ID, team ID, whether it is part of macOS, its process and parent IDs, and its terminal. Read from the records the extension keeps in the Mac's unified log. Each record is marked with whether it came from the real extension (`extension_verified`): the agent checks the code signature, user and start time of the process that logged it |
| Whether Privileges backs a grant | Only with Privileges 2.6 or later and its system extension on (macOS 14 or later). The agent also reads the lines `PrivilegesDaemon` writes to the unified log when it grants or ends admin rights, as well as the extension's records, to check that a grant claimed through the hook really came from Privileges. Before it trusts a line it looks at the process that logged it in the Mac's process list: its code signature (signing ID and team), the user it runs as and when it started. It sends only the result: on each grant, whether Privileges' log confirmed it (`privileges_log`), when, and which source (`daemon`, `extension`); and, when a claim is refused or accepted without that confirmation, the account, what was claimed (`grant`, `renewal` or `give_back`), the reason, the UID of the process that sent it and, if a line was found, when and from which source. It sends no log line and no process details of its own |
| Renewals in SAP Privileges | Only while a Privileges session is open and MDM doesn't turn renewals off. At each heartbeat the agent reads the line SAP's `PrivilegesAgent` logs when someone renews (the account and the minutes), and checks the process that logged it: the executable's UUID as the log recorded it, and in the process list its code signature, user and start time. It sends only the renewal: an `elevation.granted` for the open session with its new expiry and the minutes. It sends no log line and no process details |
| Permanent admin use: sign-ins | Only for accounts in `PermanentAdmins`, always on. Each sign-in at the Mac (login window or fast user switching), in Terminal or over interactive SSH: when it started and ended, the terminal, and for SSH the address it came from. A Terminal tab opened while the account is signed in at the Mac is part of that sign-in, not a sign-in of its own. Read from macOS's sign-in records (utmpx and wtmp) |
| Permanent admin use: prompts and screen sharing | Each time one of these accounts' name and password is typed into an admin prompt on another user's session: whose session, the authorisation right, and the app that asked, when the log names it. Each screen sharing connection that signs in as one of these accounts: when the connection was authenticated (when it closes, for a shared screen) and the viewer's address, one event per connection |
| Permanent admin use: how prompts and screen sharing are read | Uses that differ only in time are sent as one event, with a count and the time of the last, so a script approving 300 prompts within one heartbeat sends one; at most 20 events are sent for each heartbeat, and the last says how many more groups were left out. Read from the Mac's unified log at each heartbeat (every 5 minutes by default), so only as far as macOS keeps those lines |
| Permanent admin use: not recorded | `sudo`, `su`, and SSH file copies or one-off commands that open no terminal (`scp`, `ssh host command`) aren't recorded until Apple grants Altiward the Endpoint Security entitlement: macOS keeps no log line for them. So no command is ever collected. Permanent admin use is evidence, not an alert. `sudo altiward-agent permanent-uses` prints what the agent reads |
| What changed while someone was admin | New or changed LaunchDaemons and LaunchAgents (their path, label, program and arguments), new sudoers rules, new SSH keys allowed to log in (their type and fingerprint, never the key), new local accounts (name, ID and whether it is an admin), and Remote Login or Screen Sharing switched on. Only changes made while an elevation was open are sent; the Mac keeps the last snapshot in the agent's own folder |

The agent does **not** collect the Mac's name, the Mac's own IP address, process or command
history (beyond the one process behind each change above), the contents of people's files, browsing, keystrokes or location. (Your server sees the address each
connection comes from, as any web server does.)

The event format is published in full in `docs/schema/event.schema.json` in the source
repository, and Altiward can send it to you. The server rejects any field it doesn't
define.

## Connections

### From the Mac

The agent connects only to the server address in your MDM profile (`ServerURL`), over
HTTPS. It contains no third-party code, and makes no connections to Apple, SAP, Altiward
or anyone else. It:

- enrolls once with the enrolment token from your profile, registering a key it makes
  on the Mac and saying whether that key is in the Mac's Secure Enclave;
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
details. That includes every permanent admin use event the agent sends: sign-in
times, terminals and SSH addresses, who approved prompts, and screen sharing viewers' addresses, as listed above. Console
actions go there too, naming the person who made them.

The server also raises an `agent.enrollment` event of its own each time a key enrols. Its
state is `enrolled` for a Mac's first key, or its first after earlier ones were revoked
with approval off, `pending` for a new key waiting for an admin's approval, and `replaced`
for a new key that took the place of the active one without approval. It carries the Mac's
serial, hardware UUID and agent version (from the agent's `User-Agent`), the new key's
device ID, its SHA-256 fingerprint and where the Mac says it is kept, and the enrolment
token's name (`token:` and a short fingerprint, never the token). When a key was active
before, it also carries that key's device ID and storage and whether the two keys came
from the same hardware UUID. It holds no public key. A Mac that sends its key again, as a
retry, raises nothing new.

In the example deployment, Caddy also asks Let's Encrypt for TLS certificates unless you
provide your own. If you pull the image from the registry instead of loading the file,
Docker connects to `ghcr.io`. With the Deploy to Azure template, Azure pulls the images
from `ghcr.io`, Caddy's included, and Container Apps gets the certificate
for your own domain.

### In the browser

The console loads everything from your server: no fonts, scripts or analytics from
anywhere else. Its content security policy allows only its own origin, and, while the
update check is on, requests to `https://api.github.com`.

**The update check.** When someone with the admin role opens Overview or Settings, their
browser asks GitHub's public API for the release list
(`GET https://api.github.com/repos/Altiward/altiward/releases`): at most once a day per
admin's browser after a successful check, and at most once an hour while GitHub can't be
reached. When the list doesn't include the running server's version yet, as just after an
upgrade, the browser asks again at most once an hour, and keeps the list it has if that
fails. **Check now** in Settings › Updates asks straight away, at most once a minute. The answer is
kept in that browser's local storage for 24 hours, or in memory
for the tab if local storage is blocked. The request carries no
cookies, no referrer and no versions, so it says nothing about your fleet. GitHub sees
what any website sees of a request from a browser: its IP address and user agent, and,
in the `Origin` header browsers add to every request to another site, the console's
address (such as `https://altiward.example.com`). The browser compares the versions
itself and shows a notice when a newer server or agent is out. Viewers and operators
never make the request. To turn it off for everyone, set
`ALTIWARD_UPDATE_CHECK=false` in `.env` and run `docker compose up -d`: the console then
asks nobody, and its content security policy no longer allows `api.github.com`.

**Appearance.** The theme and light or dark someone picks in Settings › General stay in their
browser's local storage. They never reach the server. So do an admin's dismissed update
notices and their **Show pre-releases** choice.

## What the server stores

Everything is in your Postgres database.

| Data | Kept |
| --- | --- |
| Every event from every Mac, in full, and each `agent.enrollment` event the server raises | Forever, for now |
| Elevation sessions, including the person's UPN and reason | Forever, for now |
| Each Mac's latest state: versions, admins, health, its open permanent admin sign-ins (up to 20) and its newest 20 other permanent admin uses (the console shows up to 10, open sign-ins first) | Forever, replaced as it changes |
| Each Mac's enrollment: serial, hardware UUID, **public** key, and whether the Mac says its key is in its Secure Enclave | Forever; revoking stops the Mac reporting |
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
  revoked Mac. The agent stores the Mac's serial and hardware UUID with its key, and
  enrols a new key if it finds the store on a different Mac.
- **Where the Mac's key lives.** In the Mac's Secure Enclave, on Macs that have one
  (Apple silicon, and Intel Macs with a T2 chip) and enrolled with agent 0.2.0 or later.
  The agent keeps a handle to it in a file under `/Library/Application Support/Altiward/`
  that only root can read, and only that Mac's Secure Enclave can use the handle, so a
  copy is no use anywhere else. Someone with admin rights on the Mac can still have it
  sign while they're there. On other Macs, and on Macs that enrolled before agent 0.2.0
  until they enroll again, the key itself is in that file. That protects it from standard
  users but not from someone with admin rights on the Mac. Revoking a Mac's key in
  **Enrollments** makes it enroll again with a new one. The key isn't in the Keychain, so
  removing the agent with `--purge` leaves nothing behind.
- **The enrolment token** lets a Mac enrol, and does nothing else. It is in the MDM
  profile, so anyone on a Mac can read it. A new enrolment shows in **Enrollments**, where
  an admin can revoke it. It also reaches your SIEM as an `agent.enrollment` event.
  **Approve Macs that enrol again** is on by default: a new key for a serial that enrolled
  before waits for approval, even after its earlier key was revoked. An earlier active key
  stays valid until approval. Server 0.8.0 also enables approval once for existing
  tenants; admins can explicitly turn it off afterwards. A new key whose hardware UUID
  differs from the earlier active key's waits for approval whatever the setting. With
  approval off, anyone with the shared token can replace an enrolled Mac's identity by
  naming its serial and hardware UUID, even when the earlier key is protected by the
  Secure Enclave. The hardware UUID is the agent's own claim, not a secret, so that rule
  catches a key made on another Mac, not someone who names the UUID. The shared token
  cannot verify ownership of a serial enrolling for the first time. Check new enrolments
  against independently verified inventory; per-device bootstrap credentials are needed
  for stronger first-enrolment assurance. Changing the token doesn't affect Macs already
  enrolled.
- **Console and agent tokens** are kept in the server's `.env` file (keep it `chmod 600`).
  The server holds only their SHA-256 digests in memory and records each by a fingerprint,
  never the token.
- **Console sessions** are an HttpOnly cookie, Secure and `__Host-` prefixed over HTTPS,
  with SameSite=Lax and a CSRF token on every change. The database stores a hash of
  the session ID, not the ID itself.

## On the Mac

The agent keeps one database, `/Library/Application Support/Altiward/agent.sqlite`,
readable only by root. It holds events waiting to send (removed once your server
confirms them), the elevations open now, the Mac's key (or the handle to it in the Secure
Enclave), and revoke results (removed 30
days after they are reported). For checking grants against Privileges' log it also holds:

- each grant claim from the hook while it waits, up to a minute, for the log: the account,
  the reason the person typed, the UID of the process that sent it and when it arrived. It is
  removed once the claim is confirmed or refused;
- the process ID and start time of the last 20 processes it verified as Privileges'
  extension, so it can check older records against the process that wrote them;
- the time and logging process ID of the log lines that confirmed a claim, for 5 minutes,
  so one line can't confirm two claims;
- when it first found Privileges' log available, and whether the extension has logged a
  grant the daemon's line confirmed.

It logs to the Mac's unified log under `com.altiward.agent`.

## Network and transport

- **TLS** is handled in front of the server: by Caddy in the example deployment, by the
  Container Apps ingress with the Deploy to Azure template, or by your load balancer. The
  server itself listens on plain HTTP inside the deployment.
- **Two hostnames.** Only the agent endpoints face the internet. The console hostname
  accepts only the networks you list in `ALTIWARD_CONSOLE_ALLOW`. The Deploy to Azure
  template serves both on one address, and its caddy container applies the same rule by
  path.
- **The database connection** in the example deployment stays on Docker's internal
  network without TLS. With your own Postgres, use `sslmode=require` or stronger
  ([An existing Postgres](install.md#an-existing-postgres)). The Deploy to Azure template
  keeps the database on a private network, with no public endpoint, and connects over
  TLS with the certificate checked.
- **Logs.** The server logs to standard output, naming Macs by serial. With the Deploy to
  Azure template, Azure keeps them in the template's Log Analytics workspace for 30 days.

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
