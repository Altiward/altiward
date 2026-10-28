# Data handling

What Altiward collects, where it keeps it, and where it sends it, for your security and
privacy review. You run the server ([install guide](install.md)), so all of this stays
on your infrastructure. The Altiward project receives none of it.

## In short

- **Nothing is sent to Altiward.** The agent talks only to your server. The server talks
  only to your database and to the SIEM, identity provider and Microsoft Intune (through
  Microsoft Graph) you configure. It never updates itself: the host contacts GitHub only
  when an admin runs `upgrade.sh` with a version. There is no telemetry, crash reporting
  or registration. Altiward is open source (Apache 2.0) and has no licence to check, so
  nothing in it can stop working over one.
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
| The person | macOS short name, and their UPN (sign-in name) if you map one in the MDM profile (`UserPrincipalNames`). A person's UPN comes only from the profile, never from the directory. With Intune connected, the server also reads each Mac's primary user from Intune and shows it, but never puts it on a person's events |
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

- enrols with the enrolment token from your profile, registering a key it makes on the Mac
  and saying whether that key is in the Mac's Secure Enclave;
- replaces that key from time to time (key rotation): a file key moves into the Secure
  Enclave where the Mac has one, and a file key on another Mac is replaced every 30 days.
  It sends the new key's public half, whether it is in the Secure Enclave, and a proof
  signed with the new key, in a request signed with the old one. It doesn't use the
  enrolment token for that;
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
| Microsoft Entra ID (or, with a managed identity, the Azure VM's metadata service at 169.254.169.254, or the container app's identity endpoint) and Microsoft Graph (`graph.microsoft.com`) | Reading the Macs Intune manages, every 15 minutes | `ALTIWARD_INTUNE_*` |

**What the server reads from Intune:** the macOS devices Intune manages, with each one's
Intune device ID, serial number, Entra device ID, primary user's UPN, device name and last
check-in (and its operating system, which isn't kept). It asks Graph for those fields only,
and never changes anything in Intune. The permission it needs,
`DeviceManagementManagedDevices.Read.All`, would let it read every device Intune manages,
on every platform. None of it is sent to your SIEM.

**What your SIEM receives:** each event as an OCSF record, with the Mac's serial and
macOS version, the person's short name and UPN, the reason they typed, and the event's
details. That includes every permanent admin use event the agent sends: sign-in
times, terminals and SSH addresses, who approved prompts, and screen sharing viewers' addresses, as listed above. Console
actions go there too, naming the person who made them. So does what the server does
by itself ([How long history is kept](#how-long-history-is-kept)): removing old history or a
Mac that stopped checking in, and revoking that Mac's keys. Those entries name the server
(`altiward:server`) as the actor, never a person.

Health readings, which are most of what the server stores, are never sent to a SIEM, and
neither are the results of commands. The SIEM gets the admin group instead, as described
next.

The server also raises an `agent.enrollment` event of its own each time a key enrols, a
Mac replaces its key by rotation, or a key that rotation replaced is used again. Its state
is `enrolled` for a Mac's first key, or its first after earlier ones were revoked with
approval off, `pending` for a new key waiting for an admin's approval, `replaced` for a
new key that took the place of the active one without approval, `rotated` for a new key
that replaced the Mac's own by rotation, and `rotated_key_used` when a key that rotation
replaced signs a request again. It carries the Mac's serial, hardware UUID and agent
version (from the agent's `User-Agent`), the new key's device ID, its SHA-256 fingerprint
and where the Mac says it is kept, and the enrolment token's name (`token:` and a short
fingerprint, never the token), which a rotation doesn't use and so doesn't carry. When a
key was active before, it also carries that key's device ID and storage and whether the
two keys came from the same hardware UUID. A `rotated_key_used` event carries instead the
replaced key's device ID and fingerprint, the device ID of the key that replaced it, the
device ID of the key the server revoked because of it (if any), and the agent version
that sent the request. It is raised at most once a day for each replaced key, unless that
use revoked a key. None of these events holds a public key. A Mac that sends its key again, as
a retry, raises nothing new.

For these enrolment events, CEF puts the token fingerprint in `suser` and the device ID
the event names (the new key's, or the replaced key's for `rotated_key_used`) in `cs5`
with label `target`. Sentinel also puts the token fingerprint in its `UserName` column.
For the two rotation states, which carry no token, both hold the Mac's serial instead.
The full OCSF record carries the same fields as described above.

**The admin group.** The server also raises an `agent.admin_group` event of its own, so
that your SIEM keeps who was in each Mac's admin group after the health readings that
recorded it have expired. It is a record, not a detection. Its state is `changed` when a
health reading's `admin` group members differ from the group last sent for that Mac, and
`snapshot` for a Mac's first reading, and once a day for each Mac that isn't retired,
checked in during the last 24 hours and has had a group sent. It carries everyone in the
group at that reading (macOS short names, including anyone elevated at that moment), the
configured standing admins (`PermanentAdmins`, which is not membership), the ID and time of
the health reading it comes from, and, for `changed`, who was added and who was removed.
For each person added it also carries the session ID and source of the matching open
session in the reading, when there is one. A list holds at most 200 names, fewer if very long
names would make the event too large, and the event says how many were left out. A change
to the standing admins alone sends nothing. Altiward keeps the group last sent for each
Mac in its latest state, and, to make these events' IDs unguessable, a secret the database
makes once and never shows or sends.

Each event reaches the SIEM as OCSF Group Management (3006) records: one for each person
who joined (Add User) or left (Remove User), or for each member of a snapshot, and one for
the Mac, with the full lists and their counts even when the group is empty. CEF puts the
person's name in `duser`, as does Sentinel's `UserName` column, and the Mac's record names
no one. The volume is about one record for each admin on each Mac every day, one for each
Mac every day, and four for each elevation: two for the person (added, then removed) and
two for the Mac. The first time a server starts after upgrading to the version that
raises these events, a one-off job raises them from the readings already stored, and
history expiry waits for it. `replay-exports` sends them to a SIEM connected later like
any other event, while they are kept.

In the example deployment, Caddy also asks Let's Encrypt for TLS certificates unless you
provide your own. If you pull the image from the registry instead of loading the file,
Docker connects to `ghcr.io`. With the Deploy to Azure template, Azure pulls the images
from `ghcr.io`, Caddy's included, and Container Apps gets the certificate
for your own domain.

The server never fetches updates itself. When an admin runs `upgrade.sh` with a version,
the host downloads that release's files from GitHub with `curl` (from `github.com`, which
sends them from `release-assets.githubusercontent.com`), through `HTTPS_PROXY` if it's
set. The requests name only the files, nothing about your fleet. Given a directory of
release files instead, `upgrade.sh` contacts nobody.

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
| Every event from every Mac, in full, health readings included, and each event the server raises itself (`agent.enrollment`, `agent.silent` and `agent.admin_group`) | For the history period, never while a SIEM still waits for it |
| Elevation sessions, including the person's UPN and reason | For the history period once ended, with their events. A session still open stays, with all its events, however old |
| Each Mac's latest state: versions, admins, health, the admin group last sent to your SIEM, whether an admin has retired the Mac, its newest 20 alerts, its open permanent admin sign-ins (up to 20) and its newest 20 other permanent admin uses (the console shows up to 10, open sign-ins first) | Replaced as it changes, until the Mac is removed. The newest alerts and uses can be older than the history period while the Mac is kept |
| Each Mac's enrolment: serial, hardware UUID, **public** key, whether the Mac says its key is in its Secure Enclave, and the fingerprint of the enrolment token it used (never the token). For each key, also the key it replaced by rotation, when the Mac signed that rotation, and when a use of the key after it was replaced was last reported | Forever, even after the Mac is removed; revoking stops the Mac reporting |
| Commands sent from the console, who sent them, and their results | For the history period |
| Activity: every change made in the console, every sign-in, and what the server does by itself | Forever by default; or from 365 days, with `ALTIWARD_AUDIT_RETENTION_DAYS` |
| Console sign-in sessions: the person's email, name, identity-provider ID and role | 12 hours at most, 1 hour idle; removed on sign-out, or when an admin ends it |
| Events waiting for each SIEM | Until the SIEM accepts them |
| When each SIEM last accepted something | Replaced at each delivery |
| When each SIEM was connected (the first time the server started with it configured), or the date its history was replayed from if earlier | Forever |
| When the server was set up, whether the admin group has been sent from stored readings, and the secret that makes the IDs of the server's own events unguessable | Forever |
| With Intune connected, each Mac Intune manages: its Intune device ID, serial number, Entra device ID, primary user's UPN, device name and last check-in. Also when the copy was last refreshed, and its last error | Replaced at every sync, every 15 minutes; a failed sync keeps the last copy. Deleted when Intune is turned off, at the server's next start |

### How long history is kept

The history period covers events, sessions, commands and Macs. An admin sets it in
**Settings › General** under **Keep history for** (`history_days` in the settings API):

- **Default.** One year, if the server has a SIEM connected (at least one SIEM configured in
  `.env`), and for good if it has none.
- **A number of days,** from 90 to 3650. It applies whether or not a SIEM is connected.
- **Keep for good.** Nothing is removed.

`GET /v1/retention` reports the period in force and why. Once a day, the server removes,
by its own clock, what is older than the period:

- events it received before the cutoff, apart from those in an elevation session that stays;
- elevation sessions that ended and last changed before it, with all their events;
- commands created before it, results included;
- each Mac whose last check-in is before it, with its sessions, events and commands, and its
  latest state. Its active and pending keys are revoked first, so a Mac that comes back
  enrols again and waits for approval like any re-enrolment. Its enrolment keys stay, and
  that is what makes it a re-enrolment.

A Mac is kept, and looked at again at the next run, when only its own clock says when it
last checked in, when the server received any event for it within the period (its own alerts
included), when it has an open session, or when a key for it was created or approved within the
period. A Mac that an admin retired goes the same way, once its last check-in is older than
the period.

It never removes:

- an event a SIEM is still waiting for;
- under the default period, an event received before the latest SIEM was connected. Connecting
  a SIEM to an old database therefore removes nothing from before it until you send that
  history to the SIEM with `replay-exports` ([Connect your SIEM](install.md#4-connect-your-siem)),
  which moves that date back to the date it replays from. A period you set yourself isn't
  held back by this, but still never takes an event a SIEM is waiting for;
- anything from the last 90 days, whatever the setting. Postgres refuses to delete such
  rows, whatever the server asks;
- Activity (which has its own period), console sign-in sessions, SIEM delivery state or enrolment keys.

Expiry doesn't start until the admin group has been sent from stored readings (above), which
reads the health readings that expiry removes.

Each run that removes anything writes one `expire_history` entry to Activity for the
organisation: the cutoff, the period and why, and counts. Each Mac it removes gets a
`remove_device` entry, with its serial, its last check-in, counts, and the event ID of its open
silence alert if it had one, and each key it revokes gets a `revoke_enrollment` entry. All have
the actor `altiward:server`, and they reach your SIEM like any other. A SIEM added later can be
sent past events only while the server still keeps them.

Once expiry runs, events are no longer the full history, so nothing is ever rebuilt from
them. An event an agent sends again after its session was removed is stored as new. That needs
an acknowledgement lost for longer than the period, at least 90 days, while the Mac kept
checking in.

Activity entries can't be edited, and a database rule allows deleting only entries more
than 365 days old. Entries your SIEM hasn't received yet are never removed. Your
identity-provider groups aren't stored, only the role they map to.

Everyone who can sign in to the console, viewers included, sees each Mac's serial number,
name, primary user and last check-in from the Intune copy, including Macs that don't run
Altiward. Intune's and Entra ID's device IDs aren't shown.

Back up and protect the database as you would any system holding staff names and
security records ([Backups](install.md#backups)).

## Secrets and keys

- **Mac keys.** Each Mac makes its own key pair when it enrols. The private key stays
  on the Mac; the server stores only the public key. Every request after enrolment is
  signed with it, and the server refuses requests more than 5 minutes old or from a
  revoked Mac. The agent stores the Mac's serial and hardware UUID with its key, and
  enrols a new key if it finds the store on a different Mac.
- **Key rotation.** The agent replaces a Mac's key by itself: a file key moves into the
  Secure Enclave on a Mac that has one, and on other Macs a file key is replaced every 30
  days. The old key signs the request that introduces the new one, so no approval is
  needed, and the server revokes the old key and records which key replaced it. A copied
  key therefore goes stale. If a replaced key is used again, the server treats the Mac's
  identity as held by two parties, revokes the Mac's current key (when the replaced key
  was replaced in the last 30 days), and raises an alert. The Mac then enrols again, and
  waits for approval when approval is on.
- **Where the Mac's key lives.** In the Mac's Secure Enclave, on Macs that have one
  (Apple silicon, and Intel Macs with a T2 chip). The agent keeps a handle to it in a file
  under `/Library/Application Support/Altiward/` that only root can read, and only that
  Mac's Secure Enclave can use the handle, so a copy is no use anywhere else. Someone with
  admin rights on the Mac can still have it sign while they're there. On other Macs, the
  key itself is in that file, and so it is on a Mac whose Secure Enclave failed at
  enrolment, until the agent moves it there by rotation. A key in a file is protected from
  standard users but not from someone with admin rights on the Mac. Revoking a Mac's key
  in **Enrollments** makes it enrol again with a new one. The key isn't in the Keychain,
  so removing the agent with `--purge` leaves nothing behind.
- **The enrolment token** lets a Mac enrol, and does nothing else. It is in the MDM
  profile, so anyone on a Mac can read it. A new enrolment shows in **Enrollments**, where
  an admin can revoke it. It also reaches your SIEM as an `agent.enrollment` event.
  **Approve Macs that enrol again** is on by default: a new key for a serial that enrolled
  before waits for approval, even after its earlier key was revoked. An earlier active key
  stays valid until approval. A new key whose hardware UUID differs from the earlier active
  key's waits for approval whatever the setting. With approval off, anyone with the shared
  token can replace an enrolled Mac's identity by naming its serial and hardware UUID,
  even when the earlier key is protected by the Secure Enclave. The hardware UUID is the
  agent's own claim, not a secret, so that rule catches a key made on another Mac, not
  someone who names the UUID. The shared token cannot verify ownership of a serial
  enrolling for the first time. Check new enrolments
  against independently verified inventory, or turn on **Approve every new Mac** so each
  Mac's first key waits for approval too; per-device bootstrap credentials are needed
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
Enclave) and its public key, the server's clock offset it last learnt, and revoke results
(removed 30 days after they are reported). While the agent is replacing the Mac's key and
doesn't yet know the server's answer, it also holds the replacement key (or its handle), a
copy of the key it replaces, and the last answer that kept it waiting (such as an HTTP
status and the start of the reply, for `altiward-agent status`), removed as soon as the
answer is known. For checking grants against
Privileges' log it also holds:

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
last error, whether each SIEM, the identity provider and Microsoft Graph accept a
connection (and the Azure VM's metadata service or the container app's identity endpoint,
when Sentinel or Intune uses a managed identity), when the Intune sync last succeeded and
its last error, and when the server was set up.

It hides every secret: tokens, client secrets, the database password. It holds no event
contents, names or reasons, only counts. It sends nothing: you read it, then decide
whether to send it.

## Releases

Every release is signed by the release workflow in the Altiward repository on GitHub, so
you can check that the files came from there unchanged ([Checking a release](install.md#checking-a-release)). The
Mac package is also signed with Apple's Developer ID and notarized. Each release lists
its open-source components and their licences in `THIRD_PARTY_NOTICES.md`.

When anything on this page changes, the release notes say so.
