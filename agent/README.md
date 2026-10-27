# Mac agent

The Altiward agent is what the package built here installs on each Mac. It works alongside
SAP Privileges: Privileges grants admin rights, and the agent watches and enforces them.
It never grants admin itself.

`make package` builds the Mac package, `Altiward-<version>.pkg`. It installs
`Altiward.app`, which holds two programs:

| Program | Source | What it does |
| --- | --- | --- |
| `altiward-agent` | [`Sources/AltiwardDaemon`](Sources/AltiwardDaemon) | The daemon, a root LaunchDaemon. It watches the `admin` group, verifies each change the hook reports, keeps the session ledger and a durable outbox, alerts on or enforces expiry, runs revoke commands from the console, sends the heartbeat, runs the tamper checks and delivers events to your server. |
| `altiward-hook` | [`Sources/AltiwardHook`](Sources/AltiwardHook) | SAP Privileges' post-change hook, installed as `Altiward.app/Contents/MacOS/Altiward` (the name Privileges shows) and set as its `PostChangeExecutablePath`. It only tells the daemon that something changed: it parses `$1 user`, `$2 admin\|user` and `$3 reason`, forwards them over XPC and exits within 5 s whatever happens. |

[`AltiwardCore`](Sources/AltiwardCore) is the library both share, and holds everything
testable: the event model, the SQLite store, `ElevationTracker`, `DeliveryLoop`, remote
commands, the device key and the system probes.

```
Privileges ──$1 $2 $3──▶ altiward-hook ──XPC──▶ altiward-agent ──HTTPS──▶ API
                                                    │  ▲
                              admin group (mbr_*) ──┘  └── heartbeat every 5 min
                                                    ▼
                                         SQLite: outbox + open sessions
```

## What the daemon does

- **Records each change Privileges reports.** The hook's claim is checked against the
  real `admin` group, and the event says whether they agree (`verified`). With Privileges'
  own log available, a grant claim is held until the log confirms it (see the trust model). A grant's
  expiry is the one Privileges set: `ExpirationInterval` when MDM sets it, or the duration the
  person picked, read from Privileges' own timer and capped by `ExpirationIntervalMax`. Reading the
  timer can take seconds and the hook waits only 5 s for its answer, so a grant claim that
  needs it is also held, without the log or for a permanent admin, and recorded straight
  after the hook has its answer (#91).
- **Keeps every event until your server has it.** Each event is written to the outbox in
  the same transaction as the ledger, and removed only once the server acknowledges it.
  While the server can't be reached it retries with backoff, up to an hour apart, and sends
  at once when the network comes back or the server answers its command poll.
- **Raises admin rights nobody granted** as `admin.out_of_band`, once they have gone 30
  seconds without a grant, checked every 15 seconds; the wait is longer than a Privileges
  hook can take to report a grant. Accounts in `PermanentAdmins` are left out (their use is
  recorded, below). By default
  it only reports them; `OutOfBandEnforcement` (below) can remove them. With
  Privileges 2.6+ and its system extension on (macOS 14+), the event names the process
  that added them (`detail.instigator`), read from the extension's unified log entries and
  marked `extension_verified` when the agent matched the entry to the real extension.
- **Sends a heartbeat** every 5 minutes (`HeartbeatInterval`). It reconciles the `admin`
  group with the ledger, closing sessions whose revoke never arrived and raising anything
  the 15-second check missed, and sends `agent.health`.
- **Acts on expiry,** each heartbeat, once rights from a Privileges grant outlive their
  expiry by `ExpiryGraceMinutes` (default 5). `ExpiryEnforcement` decides what happens:
  `alert`, the default, sends `elevation.overdue` once per expiry and leaves the rights;
  `enforce` removes the user from `admin` and sends `elevation.expired_enforced`; `off`
  does nothing. A grant Privileges gives no expiry never becomes overdue. Permanent admins
  and rights nobody granted are never removed by expiry.
- **Can remove admin rights nobody granted,** each heartbeat, once they have lasted
  `OutOfBandGraceMinutes` (default 5, minimum 1) since the agent raised them.
  `OutOfBandEnforcement` decides what happens: `alert`, the default, only raises
  `admin.out_of_band`, as before; `enforce` removes the user from `admin` at the next
  heartbeat and sends `admin.out_of_band_removed`, so it acts up to `HeartbeatInterval` late.
  Any other value means `alert`. The agent counts as a human admin any member of `admin`
  with a UID of 500 or more, and any direct member of `admin` other than `root` and `_`
  accounts, hidden ones included. So `enforce` also removes the LAPS account your MDM manages, and any hidden
  management account with a low UID, unless it is in `PermanentAdmins`. It never removes a
  permanent admin and keeps at least one standing admin: a permanent admin who is admin now,
  or else the out-of-band admin it has seen longest. Someone holding admin through a
  Privileges grant doesn't count, since those rights end too, and nor do admins still in
  their grace period or not yet raised. Of admins raised at the same moment, as on a fresh
  install, it keeps the one whose short name sorts last.
  It pauses all removals while the `privileges_hook` tamper check (**Privileges reports to
  Altiward**) fails: Privileges' hook path or checksum isn't Altiward's, so Privileges won't
  run the hook and every Privileges grant would look like rights nobody granted. A
  `HookCodeRequirement` that doesn't match the hook isn't covered: the daemon rejects the
  hook's calls, so in `enforce` mode real Privileges grants are removed after the grace
  period. Check that `HookCodeRequirement` names the right Team ID before turning `enforce`
  on. A kept, paused or failed removal leaves the finding open, retries at every heartbeat
  and is logged on the Mac. A Privileges grant whose hook never reached the agent looks like
  rights nobody granted and can be removed; the person can request again. Upgrade the
  server to 0.3.0 first.
- **Records use of permanent admin accounts** (`admin.permanent_use`), always on for every
  account in `PermanentAdmins`. It is evidence, not an alert: it changes nothing in
  **Admins now** or the alerts.
  - *Sign-ins* come from macOS's sign-in records (utmpx and wtmp), checked every 15
    seconds: at the Mac (login window, fast user switching), in Terminal (`login`) and
    over interactive SSH, which also records the address it came from. A `started` event
    follows within about 15 seconds, and an `ended` event at sign-out with both times. A
    sign-in shorter than that is reported by the next heartbeat, and one while the agent
    was stopped when it starts, up to a day back. A Terminal tab opened while the account
    is signed in at the Mac is part of that sign-in, not a use of its own; `login` in
    someone else's Terminal is recorded.
    A sign-in whose process has gone, but which macOS still lists, ends as `noticed`.
  - *Prompt approvals* are a permanent admin's name and password typed into an admin
    prompt on another user's session: whose session, the authorisation right, and the app
    that asked, when the log names it.
  - *Screen sharing* is one event for each connection that signs in as the account, with
    the viewer's address, read from `screensharingd`'s log line. The viewer types a short
    name or the account's full name, in any case; it is matched to the short name listed
    in `PermanentAdmins`, which is the event's user. A wrong password isn't a use. The
    line is written when the connection starts ("Log In as Yourself") or when it closes
    ("Ask to Share Screen"), so the event has a `started` time and no end.
  - Prompts and screen sharing that differ only in time are one event, with a `count` and
    the time of the `last`: a script that approves 300 prompts within one heartbeat sends
    one. Each heartbeat sends at most 20 such events, and the last carries `truncated`,
    how many more groups it left out.
  - Prompts and screen sharing are read from the unified log each heartbeat.
  - Not recorded until Apple grants the Endpoint Security entitlement: `sudo`, `su`, and
    SSH file copies or one-off commands (`scp`, `ssh host command`) that open no terminal.
    macOS doesn't keep a log line for them.
  - `sudo altiward-agent permanent-uses [HOURS]` prints what the agent reads (default 24
    hours; run as root).
  - Needs server 0.4.0. The SIEM gets every event the agent sends; for the console, the
    server keeps each Mac's open sign-ins and its newest 20 other uses.
- **Runs revokes from the console** (below), removing the user from `admin` itself.
  Permanent admins are never removed.
- **Runs tamper checks** each heartbeat and sends `agent.tamper` when one changes: the
  LaunchDaemon plist, the app's code signature, seven settings set outside MDM
  (`ServerURL`, `PermanentAdmins`, `ExpiryEnforcement`, `ExpiryGraceMinutes`,
  `OutOfBandEnforcement`, `OutOfBandGraceMinutes`, `HookCodeRequirement`), a downgrade, and, with Privileges installed, its tamper protection, its hook setting, its timer
  stopped while someone holds rights it granted, and the Privileges settings Altiward relies
  on (an expiry cap, renewals off while `ExpiryEnforcement` is `enforce`, the hook run on
  give-backs, and revoke exclusion lists that name every permanent admin). With either enforcement setting on `enforce`
  it also fails `grant_confirmation` while it can't confirm Privileges grants against
  Privileges' log, and it reports each claim it refuses or accepts unconfirmed as `grant_claim`.
  It also reports each attempt Privileges'
  system extension blocked on Privileges since the last heartbeat (`privileges_blocked`),
  which Privileges itself only logs on the Mac. `sudo altiward-agent privileges-audit [HOURS]`
  prints what the agent reads from that log.
- **Reports what changed while someone was admin.** It snapshots launch items, sudoers,
  SSH keys, local accounts and remote access after each grant and end and on each
  heartbeat, and reports changes on the sessions open in between (`persistence.detected`).
  None of it needs Apple's Endpoint Security entitlement.
- **Maps users to UPNs** from the `UserPrincipalNames` preference. Platform SSO lookup is
  still to do.

Every setting is read when the daemon starts. It checks for changes every 15 seconds and,
when one has changed, logs which and exits for launchd to start it again with them, so a
profile that arrives after the package, or a later change, applies within seconds.

The agent enrols with the `EnrollmentToken` on first delivery, then signs every request
with its own P-256 key. On a Mac with a Secure Enclave the daemon makes the key there; on
other Macs, and on Macs that enrolled before agent 0.2.0, the key starts in the agent store
under the root-only data directory. `altiward-agent status` shows the device ID and where
the key is kept. Only the daemon can use a Secure Enclave key, so on such a Mac
`altiward-agent heartbeat`, `flush`, `commands` and `simulate-hook` do their local part
and leave the sending to the daemon. When the server's enrolment limits refuse the Mac
(HTTP 429), the agent doesn't try to enrol again until `Retry-After` says, an hour if it
doesn't say, and at most a day; it remembers that until it restarts.

The daemon also replaces the key itself (key rotation), with no admin involved. A file key
on a Mac with a Secure Enclave moves into it. On a Mac without one, a file key is replaced
every 30 days, counted from when it was made; a key with no recorded date starts counting
when the agent first sees it, so an upgrade doesn't rotate every Mac at once. A Secure
Enclave key is never replaced. The daemon checks after each long poll and at least hourly,
starting 5 to 65 minutes after it starts, and only once the current key has signed a
request successfully since then. The server also wants the key to have been active for 24
hours. The Mac makes the new key, signs a proof with it, and asks the server to swap, in
a request signed by the old key. Nothing waits for approval, because the old key vouched
for the new one. Until the server's answer is known the agent keeps both keys, asks again
at most every 15 seconds, and sends nothing else signed by the old key, so events stay
queued. A command run beside the daemon (`altiward-agent heartbeat` and the others)
never rotates, and while a rotation is unresolved it sends nothing and says the daemon is
rotating the key. `altiward-agent status` shows "key rotation: in progress since
<date>" while one is. A server that doesn't know rotation (HTTP 404 or 405), or refuses
it, leaves the Mac's key in place and the agent tries again a day later (after
`Retry-After` for HTTP 429). If the server says the old key is dead, or this Mac's Secure
Enclave can't use the replacement it saved, the agent drops both keys and enrols again
(and waits for approval when approval is on).

Remote commands are fetched by a long poll the server holds for up to 50 seconds, so a
revoke lands within about a second; also after each heartbeat and when the network
returns. After an error, or with a server that doesn't hold requests, the agent waits
`CommandPollInterval` seconds (default 60) before asking again. Each command runs once;
its result is stored with the events it caused and reported until the server
acknowledges it. `altiward-agent commands` polls once.

Keep anything that reads Privileges at the edge: expiry, revoke and the heartbeat must
work without it (see [Design notes](#design-notes)).

## Design notes

**Trust model.** Privileges runs the post-change hook as the logged-in user, and that user
can run the same binary by hand with any arguments, so a hook call is a claim, not a fact.
The hook only forwards the user, `admin` or `user`, and the reason over XPC. On every call
the daemon, running as root, reads real `admin` membership with `mbr_check_membership`
and records `claimed_state`, `observed_admin` and `verified`; the server flags sessions
with an unverified claim. The daemon's clock replaces the hook's, and the caller's UID
goes into `detail.caller_uid`. `HookCodeRequirement` and Privileges' checksum pin the
hook, but that is defence in depth. Every 5 minutes the heartbeat reconciles the `admin`
group with the ledger: it closes sessions whose revoke never arrived and raises admins
nobody granted, and, with `OutOfBandEnforcement` on `enforce`, removes those admins once the
grace period has passed. That pauses while the **Privileges reports to Altiward** check
fails (Privileges' hook path or checksum isn't Altiward's), because the agent can no longer
tell a grant from rights nobody granted. A `HookCodeRequirement` that doesn't match the hook
isn't covered: the daemon rejects the hook's calls, so in `enforce` mode real Privileges
grants are removed after the grace period.

**A hand-run hook claiming a grant or a give-back.** Someone holding admin rights nobody
granted can run the hook by hand to claim a Privileges grant, or to claim they gave the
rights back so that a grant claimed next finds no out-of-band session to replace. A real
grant's hook reports within about 25 seconds and never retries, so the only real case of a
grant replacing an out-of-band session is a heartbeat that raised the rights between
Privileges changing the group and the hook arriving. With `OutOfBandEnforcement` on
`enforce`, the daemon refuses and logs on the Mac a grant claimed on a Mac without SAP
Privileges, a grant claimed more than a minute after Altiward raised the rights
(`ElevationTracker.grantReplacementWindow`), and a give-back claimed while it still sees
the user in `admin`; the rights are then still removed after the grace period. A give-back
after the rights really went ends the session as before.

**Confirming a grant claim with Privileges' log.** From Privileges 2.6.0, `PrivilegesDaemon`
writes a line to the unified log (subsystem `com.apple.defaults`, category `audit`) for each
change it makes, and with its system extension on (macOS 14 or later) the extension logs
every change to `admin` by any process, with the process that made it. A hand-run hook
leaves neither, so the agent holds a grant claim until one of them backs it.

- *Evidence.* A **daemon line** says, from its start, `SAPCorp: User <name> now has
  administrator privileges`, with the claimed user's exact short name: the reason a person
  types is later in the same line, and can't be read as a line about someone else. An
  **extension record** is an `ADMIN_ADD` for that user whose instigating process is signed
  `corp.sap.privileges.daemon` by team `7R5ZEU67FQ`; `dseditgroup` or any other SAP binary
  isn't enough, since signing IDs are pinned one by one. Evidence counts when it was logged
  from two minutes before the claim arrived (`ClaimEvidence.lookBack`: the agent was seen
  taking up to 45 seconds to handle the hook's call, #91) to a minute after it. An
  `ADMIN_REMOVE`, or a daemon line saying the user now has standard privileges, voids the
  evidence before it, so removing, re-adding and claiming within two minutes of a real grant
  doesn't work. One piece of evidence confirms one claim, remembered across restarts for 5
  minutes. If the extension logged any change for the user in the window, the latest must
  be an allowlisted add, whatever the daemon line says. Both rules look only at changes made
  at or before the claim's arrival: a real grant given back seconds after its claim arrived
  is still confirmed, not reported. A daemon line and an extension record within 5 seconds
  of each other are one grant.
- *Verification.* A line counts only if the process that logged it is verified: its pid's
  code signature has the expected signing ID (`corp.sap.privileges.daemon` for the daemon
  line, `corp.sap.privileges.extension` for the record) and team, it runs as root, and it
  **started before the line**, because pids are reused and a forger could land on a SAP
  process's pid. The log's own image path and UUID aren't trusted: a forged binary can copy
  them. The agent remembers the pid and start time of each extension instance it verified
  (the last 20), so older records are checked against the instance that wrote them; a record
  from an instance it never saw is `extension_verified: false` on `instigator` and
  `privileges_blocked`, not dropped.
- *When the log is available.* Privileges 2.6.0 or later is installed, macOS is 14 or later,
  and a running extension verifies as above. The agent decides by looking at the process,
  not at settings or version strings, which root can write.
- *Confirming afterwards.* The hook can't wait for the log: it times out after 5 seconds,
  and a refused real grant can't be recovered, since Privileges sends no second claim. So
  the daemon holds a grant claim in its store and tells the hook it is accepted for
  confirmation. The 15-second check and the heartbeat resolve it as soon as evidence
  appears, or when its minute is over. While it is held the user isn't raised as out of band.
  On confirmation the session opens exactly as before, even if the agent raised the rights
  longer than a minute ago (the confirmed grant overrides the `late` refusal), timed by the
  claim's arrival, with an expiry counted from the evidence's time, not the claim's.
  `elevation.granted` carries `privileges_log: "confirmed"`, `confirmed_at` and the
  `evidence` sources. In `OutOfBandEnforcement` `enforce` mode an unconfirmed grant is
  refused and reported (`grant_claim`, `refused`), and the user's rights become out of band
  from when the agent first saw them, so a hand-run claim doesn't lengthen the grace period.
  In `alert` mode it is accepted, marked `not_confirmed` and reported (`accepted_unconfirmed`).
  A daemon line without an extension record, while the extension's log is available, is
  held until 5 seconds after the line was logged, as the record lands a moment after the
  line and can take up to a second to be readable. Then it still confirms the grant (a real
  grant is never stripped because the extension went quiet), and fails the
  `grant_confirmation` check.
- *Renewals.* A real Privileges renewal sends no hook claim and writes no audit line, so a
  claim made while a Privileges session is open and the user is admin has nothing real to
  match. The session is renewed only when fresh log evidence confirms the claim (the log
  shows Privileges granted again). Otherwise the claim is refused in every mode, reported
  with kind `renewal`, and the session keeps its expiry.
- *Real renewals* (#90). Privileges records one only as a line from `PrivilegesAgent`,
  which runs as the user: "SAPCorp: Administrator privileges for user jdoe have been renewed
  (60 minutes)". At each heartbeat, before expiry is enforced, the agent reads these lines
  and moves the session's expiry to the line's time plus its minutes, capped by
  `ExpirationIntervalMax`, sending an `elevation.granted` with `trigger`
  `privileges_renewal`. A user could log such a line from their own program and then exec
  SAP's agent, keeping the pid, so a line counts only when the executable the log recorded
  for it is SAP's agent on disk (by its Mach-O UUID), and the process is SAP's signed agent,
  running as the user the line names and started before it. A line whose process has gone
  can't be checked and is ignored. While MDM sets `AllowPrivilegeRenewal` to `false` the
  lines aren't read at all, as no real renewal can happen, which is why that stays the
  recommendation. It is not a boundary against someone with admin rights who sets out to
  forge a binary with SAP's UUID: each renewal is sent, and capped by the maximum.
- *Binding the caller to the user.* Privileges runs the hook as the user whose rights
  changed. With the log available, a claim whose caller UID is neither the claimed user's nor
  0 is refused and reported, which stops a standard user ending someone else's session with
  a give-back. A caller is limited to 5 grant claims a minute, checked before anything
  else; those refusals are logged on the Mac and not sent, so a flood can't fill the
  outbox. Give-back claims don't count towards it. They have an allowance of their own, 5 a
  minute from one caller, in every mode and with or without the log: past it, a give-back
  that ends an open session is still recorded, so a real give-back always is, and any other
  (one that would be refused, come from another user, or end no session) is logged on the
  Mac and not sent (#96). Every other
  refusal is reported as `grant_claim` (`refused`), including the earlier ones: a grant on a
  Mac without SAP Privileges, a grant claimed too long after the rights were raised, and a
  give-back (`kind` `give_back`) while the user is still admin.
- *Without the log.* Nothing can confirm a claim. The agent keeps removing rights nobody
  granted, accepts a grant claim with the earlier checks, and marks it
  `privileges_log: "unavailable"`. With no fixed `ExpirationInterval`, the claim is held while
  Privileges' timer is read, so a refusal is reported but the hook isn't told of it. The `grant_confirmation` check fails, naming what is
  missing (it is left out unless `OutOfBandEnforcement` or `ExpiryEnforcement` is `enforce`
  and Privileges is installed). On a Mac where the agent has had the log, accepting a claim
  without it is also reported (`accepted_unconfirmed`): killing the extension and claiming in
  the restart gap is how an attacker would get here.

The residual: this is not a boundary against root. An admin is root through `sudo`, and
someone with root can still forge a line, for example by logging as a process that then
runs the genuine SAP binary (the pid and start time stay the same), or by editing
`agent.sqlite`. The aim is that the quiet routes (a hand-run claim, a claim just before the
agent raises rights, remove-give-back-re-add-claim, and endless renewal) stop working, and
that what is left needs root and leaves a tamper event. The agent doesn't check that the
log subsystem is still persisting, and it trusts the Mac's clock.

The older refusals (no Privileges installed, `late`, a give-back while still admin) still apply
in `enforce` mode, and without Privileges' log they are all there is: a hand-run
claim can keep rights nobody granted in two ways, a grant claimed before the agent raises
the rights (in the 30 seconds or so before it does, or between heartbeats), and an account
with root that removes itself from `admin`, gives the rights back, adds itself again and
claims a grant.

In `alert` mode, without the log, both claims work as before: a claimed grant replaces the
out-of-band session, shown in the console as **Followed rights without a grant** and in the
SIEM as "Replaced by a Privileges grant", and each claim renews a Privileges session, each
reported as `elevation.granted`. With the log, a claim it doesn't confirm still replaces the
session but is marked `not_confirmed` and reported, and a claim renews a session only when fresh log evidence confirms it.

**The device key stops a copy, not a person at the Mac.** Altiward watches people who hold
admin rights for a while, and admin rights can read root-only files. A key in a file could
be copied during an elevation and used later from anywhere, to send heartbeats that say all
is well or to end a session after removing the agent. A Secure Enclave key can't be copied
off the Mac: the store holds only a handle that this Mac's Secure Enclave can use. Someone
with admin rights can still have the Mac sign while they're there, or leave a root process
behind to do it later; the tamper checks and the persistence snapshot are what look for
that. The key is usable from the first unlock after boot, with nobody signed in, and only
in the session that made it, so the daemon makes it and only the daemon uses it. A key the
Secure Enclave can't use while a throwaway key works (the store came from another Mac or a
backup) is dropped and the Mac enrols again. The store also records the serial and
hardware UUID of the Mac that made the key, so a file key copied to another Mac (by
Migration Assistant, a clone or a restore) is dropped there the same way, instead of
signing as the first Mac; a key stored by an earlier agent is given this Mac's identity
and stays enrolled. A file key and a Secure Enclave key have separate records, so agent
0.1 installed over this one finds no key it can't read and enrols again with a file key.
Where the Mac says its key is kept is its own claim: the server can't check it.

**Rotation makes a copied file key go stale.** A copied file key used to work for as long
as the original did, with both holders unseen. Now the original is replaced, by the move
into the Secure Enclave or by the 30-day rotation, and the server revokes a replaced key.
A copy that is then used is refused. If the Mac and the copy both go on using one lineage
of keys, the second use shows the server two holders: it can't tell which is the Mac, so
it revokes the lineage's current key, raises a High `rotated_key_used` alert, and the Mac
enrols again, waiting for an admin's approval when approval is on. The copy's holder gets
one visible disruption, and no quiet takeover. That disruption can also be caused on
purpose, once per lineage, by anyone holding a copy of a key replaced in the last 30 days;
a copy of an older key only raises the alert. The agent never signs with a key it has
replaced, and, while the outcome of a rotation is unknown, nothing else signed by the old
key leaves the Mac, because the server would take that for a second holder. What to do
about the alert is in the [install guide](../docs/install.md#a-rotated-key-was-used).

**First-enrolment identity has limits.** Rotation proves continuity, not origin: each
key is authorised by the one before it, which says nothing about who made the first. If
someone enrolled a serial before the real Mac did, rotation carries their identity
forward, and so does a copy of a key that rotates first (the copy needn't be on the same
Mac). Where a Mac says its key is kept is its claim: a file key enrolled with a false
claim of the Secure Enclave is never rotated, and the console shows it as held in the Secure Enclave.
A genuine agent never claims that falsely, so this affects only identities someone else
enrolled. While the genuine Mac is offline, a copy that rotated holds the only working
key, and the server learns of two holders only when the Mac next connects; if the copy
is the only user, because the Mac was wiped or never comes back, there is no second
holder to notice. A server rolled back to before rotation raises no alert for any of
this while it runs. Closing these gaps takes MDM device-ID binding
([#134](https://github.com/Altiward/altiward/issues/134)) or Apple attestation. Until then,
check new enrolments against your device inventory, as the
[install guide](../docs/install.md#2-deploy-the-agent) says.

**Privileges stays at the edge.** Altiward depends on a project it doesn't control, and
must keep working when Privileges' timer is stopped or Privileges is removed. So expiry,
revoke and the heartbeat act on the `admin` group from the daemon, never through
`PrivilegesCLI` or Privileges' timer. The agent only reads Privileges: its settings and
timer, to capture a grant and its expiry, and its settings and process list entry for the
tamper checks. It never writes to them.

## Build and test

```sh
make agent-test      # from the repo root
make agent-build
```

Build output goes to `~/Library/Caches/altiward/agent-build` (`SWIFT_SCRATCH`), not
`agent/.build`. Codesign rejects build products inside an iCloud-synced folder.

## Run locally without launchd

`altiward-agent` subcommands work as a normal user when `ALTIWARD_DATA_DIR` points somewhere
writable. With the API running (`make run-api`):

```sh
make dev-hook STATE=admin REASON="installing a driver"   # as if Privileges granted you admin
make dev-hook STATE=user
make dev-heartbeat
```

or directly: `altiward-agent status | flush | heartbeat | commands | simulate-hook USER STATE [REASON]`.

## Configuration

Managed preference domain `com.altiward.agent`; see the commented example in
[`com.altiward.agent.plist`](../deploy/mdm/com.altiward.agent.plist).
Environment overrides for development: `ALTIWARD_SERVER_URL`, `ALTIWARD_TOKEN`,
`ALTIWARD_DATA_DIR`, `ALTIWARD_HEARTBEAT_SECONDS`.

The Privileges keys admins add are in
[`corp.sap.privileges.plist`](../deploy/mdm/corp.sap.privileges.plist).

## Packaging

The daemon is installed with classic launchd (the postinstall runs `launchctl bootstrap`),
not `SMAppService`: an MDM installs packages as root, often with nobody logged in and no
app running to register it.

```sh
make package          # Altiward.app + Altiward-<version>.pkg, ad-hoc signed
make package-verify   # layout, signatures, payload, install scripts, pinned checksum
```

The output goes to `~/Library/Caches/altiward/package/`:
- **`Altiward.app`** installs to `/Library/Application Support/Altiward/`. Both binaries
  are universal, with a minimum of macOS 13.
- **`Altiward-<version>.pkg`** has a postinstall that installs and bootstraps the
  LaunchDaemon.
- **`corp.sap.privileges.plist`** has `PostChangeExecutableChecksum` set to this build's
  hook. Each signed build changes the checksum, so update the site's Privileges profile
  before or together with each agent version. With a stale checksum Privileges silently
  stops running the hook, and grants show as admin rights without a grant about 30
  seconds later. The `privileges_hook` check catches it: it compares the checksum with
  the installed hook whenever MDM sets both Privileges keys, which is when Privileges
  checks it too.

`make package` prints the `HookCodeRequirement` value for the hook it built.

`Altiward.app` carries `AppIcon.icns`, the brand's graphite app icon. `make app-icon`
rebuilds it from `assets/brand/altiward-app-icon.svg`; `make package-verify`
checks that the bundle has it.

To deploy, push the package with these profiles:
- [`com.altiward.agent.plist`](../deploy/mdm/com.altiward.agent.plist): agent settings
- [`altiward-login-items.mobileconfig`](../deploy/mdm/altiward-login-items.mobileconfig):
  makes the daemon a managed background item
- the generated Privileges keys

To uninstall: `sudo "/Library/Application Support/Altiward/Altiward.app/Contents/Resources/uninstall.sh"`.
It keeps undelivered events unless you pass `--purge`.

Releases: pushing an `agent-v<version>` tag runs
[`release-agent.yml`](../.github/workflows/release-agent.yml). It signs with Developer ID, notarizes,
staples and verifies, using repository secrets only.
