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
  real `admin` group, and the event says whether they agree (`verified`). A grant's
  expiry is the one Privileges set: `ExpirationInterval`, or the duration the person
  picked, read from Privileges' own timer and capped by `ExpirationIntervalMax`.
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
  that added them (`detail.instigator`), read from the extension's unified log entries.
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
    was stopped when it starts, up to a day back.
  - *Prompt approvals* are a permanent admin's name and password typed into an admin
    prompt on another user's session: whose session, the authorisation right, and the app
    that asked, when the log names it.
  - *`sudo`* by a permanent admin records the terminal and the user it ran as, never the
    command or working directory. *`su`* to one records whose session and the terminal.
  - Prompts, `sudo` and `su` that differ only in time are one event, with a `count` and
    the time of the `last`: a script that runs `sudo` 300 times sends one. Each heartbeat
    sends at most 20 such events, and the last carries `truncated`, how many more groups
    it left out.
  - Prompts, `sudo` and `su` are read from the unified log each heartbeat, so they are
    recorded only where macOS keeps those lines: on some Macs it doesn't keep successful
    `sudo` runs. Apple's Endpoint Security, if Apple grants the entitlement, would make
    this reliable.
  - Not recorded yet, pending a test on a real Mac: screen sharing, and SSH file copies or
    one-off commands (`scp`, `ssh host command`) that open no terminal.
  - `sudo altiward-agent permanent-uses [HOURS]` prints what the agent reads (default 24
    hours; run as root).
  - Needs server 0.4.0. The server keeps the newest 20 uses per Mac for the console; the
    SIEM gets them all.
- **Runs revokes from the console** (below), removing the user from `admin` itself.
  Permanent admins are never removed.
- **Runs tamper checks** each heartbeat and sends `agent.tamper` when one changes: the
  LaunchDaemon plist, the app's code signature, seven settings set outside MDM
  (`ServerURL`, `PermanentAdmins`, `ExpiryEnforcement`, `ExpiryGraceMinutes`,
  `OutOfBandEnforcement`, `OutOfBandGraceMinutes`, `HookCodeRequirement`), a downgrade, and, with Privileges installed, its tamper protection, its hook setting, and its timer
  stopped while someone holds rights it granted. It also reports each attempt Privileges'
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

The agent enrolls with the `EnrollmentToken` on first delivery, then signs every request
with its own P-256 key. On a Mac with a Secure Enclave the daemon makes the key there; on
other Macs, and on Macs that enrolled before agent 0.2.0, the key is in the agent store
under the root-only data directory. `altiward-agent status` shows the device ID and where
the key is kept. Only the daemon can use a Secure Enclave key, so on such a Mac
`altiward-agent heartbeat`, `flush`, `commands` and `simulate-hook` do their local part
and leave the sending to the daemon.

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

Hand-run claims can still keep rights nobody granted in `enforce` mode, in two ways: a
grant claimed before the agent raises the rights (in the 30 seconds or so before it does,
or between heartbeats), and an account with root that removes itself from `admin`, gives
the rights back, adds itself again and claims a grant. The hook is untrusted and an admin
can do this. A later release will accept a grant claim in `enforce` mode only when
Privileges' own log shows Privileges added the user.

In `alert` mode both claims work as before: a claimed grant replaces the out-of-band
session, shown in the console as **Followed rights without a grant** and in the SIEM as
"Replaced by a Privileges grant". Once a session is a Privileges session, with
`ExpiryEnforcement` set to `enforce` and an expiry from Privileges' settings, the rights
end at expiry, unless they run the hook again before then: each claim renews the grant, and
each is reported as `elevation.granted`.

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
backup) is dropped and the Mac enrolls again. A file key and a Secure Enclave key have
separate records, so agent 0.1 installed over this one finds no key it can't read and
enrolls again with a file key. Where the Mac says its key is kept is its own claim: the
server can't check it.

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
