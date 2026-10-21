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
- **Raises admin rights nobody granted** as `admin.out_of_band`, once they have gone 30
  seconds without a grant, checked every 15 seconds; the wait is longer than a Privileges
  hook can take to report a grant. Accounts in `PermanentAdmins` are left out.
- **Sends a heartbeat** every 5 minutes (`HeartbeatInterval`). It reconciles the `admin`
  group with the ledger, closing sessions whose revoke never arrived and raising anything
  the 15-second check missed, and sends `agent.health`.
- **Acts on expiry,** each heartbeat, once rights from a Privileges grant outlive their
  expiry by `ExpiryGraceMinutes` (default 5). `ExpiryEnforcement` decides what happens:
  `alert`, the default, sends `elevation.overdue` once per expiry and leaves the rights;
  `enforce` removes the user from `admin` and sends `elevation.expired_enforced`; `off`
  does nothing. A grant Privileges gives no expiry never becomes overdue. Permanent admins
  and rights nobody granted are never removed by expiry.
- **Runs revokes from the console** (below), removing the user from `admin` itself.
  Permanent admins are never removed.
- **Runs tamper checks** each heartbeat and sends `agent.tamper` when one changes: the
  LaunchDaemon plist, the app's code signature, five settings set outside MDM
  (`ServerURL`, `PermanentAdmins`, `ExpiryEnforcement`, `ExpiryGraceMinutes`,
  `HookCodeRequirement`), a downgrade, and, with Privileges installed, its tamper protection, its hook setting, and its timer
  stopped while someone holds rights it granted.
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
with its own P-256 key, kept in the agent store under the root-only data directory.
`altiward-agent status` shows the device ID.

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
nobody granted.

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
