# Core event schema

[`event.schema.json`](event.schema.json) is the contract between the Mac agent and the
API. One type, `agent.silent`, is raised only by the backend; the API refuses it from
agents. The [examples](examples/) are decoded by both the Swift and Go test suites.

Changing the schema means changing, together: the JSON Schema, the fixtures,
`agent/Sources/AltiwardCore/Event.swift` and `backend/internal/event/event.go`. The Go
decoder rejects unknown fields, so drift fails loudly.

## `detail` by event type

| Type | Field | Meaning |
| --- | --- | --- |
| `elevation.granted` | `trigger` | `hook` (Privileges) |
| | `claimed_state` | What the hook said (`admin`) |
| | `observed_admin` | Real `admin` group membership when the daemon recorded it |
| | `verified` | `claimed_state` agrees with `observed_admin` |
| | `renewed` | A grant while this user's Privileges session was already open |
| | `replaced_out_of_band` | `true` when the grant replaced this user's out-of-band session, which an `elevation.revoked` with trigger `privileges_grant` ends just before it. Absent otherwise |
| | `expires_basis` | Where `elevation.expires` came from: `ExpirationInterval` or `ExpirationIntervalMax`; `PrivilegesTimer`, the duration the user picked in Privileges, read from Privileges' own timer and never later than `ExpirationIntervalMax` |
| | `caller_uid` | UID of the process that called the daemon over XPC |
| `elevation.revoked` | `trigger` | `hook`, `heartbeat`, `command` (remote revoke) `permanent_admin` (an out-of-band session's user is now in `PermanentAdmins`: the session ends and the rights stay) or `privileges_grant` (a Privileges grant replaced the user's out-of-band session: the session ends, the rights stay, and the grant's session follows) |
| | `command_id` | The console command that caused it (`command` only) |
| | `claimed_state` | As above (`hook` only) |
| | `observed_admin`, `verified` | As above. On `heartbeat` and `command` they are `false`, `true`: the daemon confirmed the rights are gone. On `permanent_admin` they are `true`, `true`: the rights are still there, as expected. On `privileges_grant` both are the admin group membership the daemon read with the grant |
| | `caller_uid` | UID of the process that called the daemon over XPC (`hook` only) |
| | `orphan` | Revoke with no open session on the device (e.g. agent installed mid-session) |
| | `inferred` | Closed without the user giving rights back: by the heartbeat because the user is no longer admin |
| `elevation.overdue` | `trigger` | `heartbeat` |
| | `expired_at` | The session's expiry |
| | `grace_seconds` | Configured `ExpiryGraceMinutes`, in seconds |
| | `observed_admin` | Always `true`: the user still holds the rights |
| | `enforcement` | `alert` or `enforce` (the agent's `ExpiryEnforcement`) |
| | `enforcement_failed` | `true` when `enforce` mode could not remove the rights; the agent retries every heartbeat |
| | `error` | Why removal failed (only when `enforcement_failed`) |
| `elevation.expired_enforced` | `trigger`, `expired_at`, `grace_seconds` | As for `elevation.overdue` |
| | `observed_admin`, `verified` | `false`, `true`: the daemon removed the rights and confirmed it |
| `admin.out_of_band` | `first_observed` | When the agent raised these rights: at a heartbeat, or at the check every 15 seconds once they had gone 30 seconds without a grant |
| | `instigator` | The process that added the user to `admin`, from SAP Privileges' system extension log (Privileges 2.6+, extension on, macOS 14+): `executable`, `signing_id`, `team_id` (empty for Apple's own), `platform_binary`, `pid`, `ppid`, `tty` (empty when not from a terminal) and `logged_at`. Absent when the extension logged nothing for this user in the last heartbeat interval plus 10 minutes |
| `admin.out_of_band_removed` | `trigger` | `heartbeat` |
| | `first_observed` | When the agent raised these rights, the same as its `admin.out_of_band` |
| | `grace_seconds` | Configured `OutOfBandGraceMinutes`, in seconds |
| | `observed_admin`, `verified` | `false`, `true`: the daemon removed the rights and confirmed it |
| `agent.health` | `admin_members` | Every human account that is admin right now |
| | `permanent_admins` | Configured standing admins |
| | `open_sessions` | `[{user, session_id, source}]` from the agent's ledger |
| | `queue_depth` | Events still waiting to be sent |
| | `privileges` | `installed`, `post_change_hook_configured`, `pass_reason_to_executable`, `expiration_interval_minutes`, `expiration_interval_max_minutes`, `enforce_privileges`, `system_extension_enabled`, `admin_budget_minutes` (`AdminBudget`, Privileges 2.7+; `null` when unset or 0) |
| | `integrity` | Each tamper check that applies on this Mac, check → passing (see `agent.tamper`) |
| | `persistence_unreadable` | Persistence locations that exist but the last snapshot couldn't read, such as a home folder privacy protection covers; empty when all were read. Missing before the first snapshot |
| `agent.tamper` | `check` | `launch_daemon`, `code_signature` (Altiward.app fails a strict signature check), `settings_managed` (one of the settings it checks comes from /Library/Preferences, not MDM), `privileges_tamper_protection`, `privileges_hook` (Privileges installed: its hook isn't Altiward's, or its checksum doesn't match Altiward's hook), `privileges_timer` (Privileges installed: someone logged in holds rights from a Privileges grant and their Privileges agent, which runs the timer, isn't running), `agent_version` or `privileges_blocked` (Privileges' system extension blocked an attempt to delete, rename, clone, add to or unload Privileges, one event per process and item each heartbeat) |
| | `state` | `failed` (the check started failing, or fails the first time it runs), `restored` (it passes again), `retired` (it was failing and no longer applies, so its alert closes) or `detected` (a one-off: a downgrade, or an attempt Privileges blocked) |
| | `problem` | What is wrong; for `retired`, why the check no longer applies (`SAP Privileges isn't installed now`); `null` when `restored` |
| | `previous_version`, `current_version` | The versions either side of a downgrade (`agent_version` only) |
| | `blocked_action`, `item` | What Privileges blocked (`DELETE`, `RENAME`, `CLONE`, `CREATE` or `EXEC`, which is unloading its launchd items) and the item's path (`privileges_blocked` only) |
| | `instigator` | The process that tried, as for `admin.out_of_band` without `logged_at`; `null` when the extension didn't say (`privileges_blocked` only) |
| | `attempts`, `first_attempt`, `last_attempt` | How many times that process tried on that item since the last heartbeat, and when (`privileges_blocked` only) |
| | `truncated` | On the last of a heartbeat's 20 `privileges_blocked` events, how many more were left out; absent otherwise |
| `admin.permanent_use` | `use_id` | UUID. A sign-in's `started` and `ended` events share it |
| | `method` | `console`, `terminal`, `ssh`, `screen_sharing`, `prompt`, `sudo` or `su`. `terminal` is a terminal with no remote host, such as `login` in Terminal; a Terminal tab opened while the account is signed in at the Mac is part of that `console` sign-in and isn't sent. The server accepts any non-empty value, so a later method needs no server upgrade first |
| | `state` | `started` or `ended` for sign-ins; `single` for prompt and screen sharing, and for any sudo, su or SSH use a later agent sees only in the log |
| | `source` | `utmpx` or `unified_log`. Both are records an admin can erase, so they corroborate rather than prove |
| | `started` | When the use began: the sign-in time macOS recorded, or the first log entry of a group |
| | `ended` | When it ended (`ended` only) |
| | `end_basis` | `logged` (macOS's sign-out or shutdown record; after a crash, which writes neither, the next boot record) or `noticed` (the agent saw the sign-in gone, or its process gone while macOS still listed it, and the time is when it noticed); `ended` only |
| | `tty` | `console`, `ttys003`, and so on (sign-ins) |
| | `remote_host` | The client's address as macOS recorded it; `null` when it didn't (`ssh` and `screen_sharing`) |
| | `on_session_of` | Short name of the user whose session it was; `null` when unknown (`prompt`) |
| | `right` | The authorisation right the prompt was for (`prompt` only) |
| | `client` | Path of the app that asked, when the log names it; `null` otherwise (`prompt` only) |
| | `run_as` | The target user (`sudo` only; Agent 0.3.0 doesn't send it) |
| | `count`, `last` | How many uses were grouped into this event since the last heartbeat, and the newest one's time (`single` only) |
| | `truncated` | On the last of a heartbeat's 20 `single` events, how many more groups were left out; absent otherwise |
| `persistence.detected` | `findings` | What is new or changed since the last snapshot, in a stable order. Each has `kind` and `change` (`added` or `modified`), plus fields by kind, below |
| | `since` | When the last snapshot was taken: the changes happened between then and `timestamp` |
| | `truncated` | Findings left out to keep the event small; `0` when all were sent |
| `agent.silent` | `state` | `silent` (the Mac hasn't checked in for the tenant's limit) or `resumed` (it checked in again) |
| | `last_seen_at` | The Mac's last check-in, by the server's clock (when it received the event, not the event's `timestamp`): before the silence for `silent`, the one that ended it for `resumed` |
| | `silent_after_seconds` | The tenant's limit when it was raised (`silent` only) |
| | `silent_since`, `alert_event_id` | The `last_seen_at` and event ID of the `silent` event this ends (`resumed` only) |

`elevation.overdue` is sent at most once per session expiry (a renewal re-arms it) and
leaves the session open. `elevation.expired_enforced` ends it.

`admin.out_of_band_removed` ends an out-of-band session; the agent sends it only when
`OutOfBandEnforcement` is `enforce`.

`agent.tamper` is sent when a check changes, not on every heartbeat: the agent keeps each
check's last result, so a restart doesn't repeat an alert. A check that stops applying
sends `retired` if it was failing, and is dropped without an event if it was passing.

`admin.permanent_use` records a use of an account in `PermanentAdmins`. Its `user` is that
account; it has no `session_id` and no `elevation`, so it is never a session. A sign-in sends
`started` and later `ended`, paired by `use_id`. A prompt and a screen sharing
connection send `single`: one event per grouped use, with `count` and `last`. Agent 0.3.0
sends `console`, `terminal` and `ssh` sign-ins, `prompt` and `screen_sharing`. It doesn't send
`sudo`, `su` or an SSH use seen only in the log: macOS keeps no log line for them, so they
wait for Apple's Endpoint Security entitlement. The server accepts them.

Older agents' events are frozen in [`compat/`](compat/), one directory per agent release,
and the server must keep accepting the last two.

`agent.silent` is raised by the backend's monitor, not the agent. Its `timestamp` is when
the backend raised it and `device` is the Mac's last known identity and versions. It
doesn't count as a check-in. Each silence is raised once: the event ID is a name-based
UUID of the tenant, serial and what it reports. Macs whose credentials were all revoked
don't alert.

`activity` is defined but not yet emitted.

### `persistence.detected` findings

The daemon snapshots the places where admin rights are used to stay on a Mac, after every
grant and end of a session and on each heartbeat. A change is reported on every session
open between two snapshots, so it says the change happened while that user held admin
rights, not that they made it. Changes while no session was open are taken in silently.
Removals aren't findings. The last snapshot survives a restart, so a session that ended
while the daemon wasn't running still gets its changes, with a wide `since`.

| `kind` | Fields | What |
| --- | --- | --- |
| `launch_daemon` | `path`, `label`, `program`, `arguments` | A plist in /Library/LaunchDaemons. `program` is `Program` or the first of `ProgramArguments`; up to 16 arguments of 512 characters each |
| `launch_agent` | As above, and `user` for one in a home folder | A plist in /Library/LaunchAgents or a user's ~/Library/LaunchAgents |
| `sudoers` | `path`, `added_lines` | /etc/sudoers or a file in /etc/sudoers.d. Only rule lines new since the last snapshot, up to 16; a file that only lost lines isn't reported |
| `ssh_authorized_key` | `path`, `user`, `key_type`, `fingerprint` | A key in root's or a user's ~/.ssh/authorized_keys (or authorized_keys2). The OpenSSH SHA-256 fingerprint, never the key or its comment |
| `local_account` | `name`, `uid`, `admin` | A new account in the directory, system accounts included. `admin` is whether it was in the `admin` group when found; may be absent |
| `remote_access` | `service` | `remote_login` or `screen_sharing` switched on |

## Versioning

Every event carries `schema_version`, always `1` so far, so the format can evolve.
