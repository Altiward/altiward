# Core event schema

[`event.schema.json`](event.schema.json) is the contract between the Mac agent and the
API. Three types, `agent.silent`, `agent.enrollment` and `agent.admin_group`, are raised
only by the backend, and the API refuses them from agents. The [examples](examples/) are
decoded by both the Swift and Go test suites.

Changing the schema means changing, together: the JSON Schema, the fixtures,
`agent/Sources/AltiwardCore/Event.swift` and `backend/internal/event/event.go`. The Go
decoder rejects unknown fields, so drift fails loudly.

## Session ownership

Every session is bound to the sending Mac's serial, hardware UUID and local account name.
The API checks the serial against the authenticated device credential. The first event
binds the session even if a revoke arrives before its grant. An accountless activity event
binds the Mac first; a later event can fill its previously unknown account, which then
stays fixed. UPN is mapping data and can change while the local account stays the same.
Agents from 1.2 send the same UPN on every event of a session: the one on record when its
grant claim arrived, or when its rights nobody granted were found. A session open while the
agent was upgraded from 1.1 has none recorded, so its events carry the UPN on record as each
is made.

An event that conflicts with an existing owner causes HTTP `409` for the whole batch.
No events, derived device/session state or SIEM obligations from that batch are stored,
and no event IDs are acknowledged. The agent keeps the batch for retry. The server logs
the conflict so an administrator can investigate an inconsistent device queue. Exact
resends of already stored event IDs remain duplicates and are not reapplied.

Postgres serialises ingestion transactions within each tenant. One transaction-level
advisory lock protects sessions whose first event has not yet created a row, and avoids
deadlocks when concurrent batches mention the same events in different orders. Other
tenants and console reads remain independent. This favours bounded lock use and atomic
ownership checks over concurrent ingestion writes within one tenant.

## `detail` by event type

| Type | Field | Meaning |
| --- | --- | --- |
| `elevation.granted` | `trigger` | `hook` (Privileges), or `privileges_renewal`: a renewal in Privileges, which sends no hook claim, read from the line `PrivilegesAgent` logs and counted only when SAP's agent logged it. A renewal carries `renewed`, `observed_admin`, `verified`, `expires_basis` and `renewed_minutes`, and no `claimed_state` |
| | `claimed_state` | What the hook said (`admin`) |
| | `observed_admin` | Real `admin` group membership when the daemon recorded it |
| | `verified` | `claimed_state` agrees with `observed_admin` |
| | `renewed` | A grant while this user's Privileges session was already open |
| | `replaced_out_of_band` | `true` when the grant replaced this user's out-of-band session, which an `elevation.revoked` with trigger `privileges_grant` ends just before it. Absent otherwise |
| | `expires_basis` | Where `elevation.expires` came from: `ExpirationInterval` or `ExpirationIntervalMax`; `PrivilegesTimer`, the duration the user picked in Privileges, read from Privileges' own timer and never later than `ExpirationIntervalMax`; `PrivilegesRenewal`, the renewal's time plus `renewed_minutes` |
| | `renewed_minutes` | How long the renewal that `PrivilegesAgent` logged lasts (`trigger` `privileges_renewal` only) |
| | `caller_uid` | UID of the process that called the daemon over XPC |
| | `privileges_log` | Whether SAP Privileges' own log backed the claim: `confirmed`, `not_confirmed` (only `OutOfBandEnforcement` `alert`: the grant was accepted, and an `agent.tamper` `grant_claim` follows) or `unavailable` (the log can't be read on this Mac, so the claim was accepted as before). Absent on a give-back, and on a grant to an account in `PermanentAdmins` |
| | `confirmed_at` | When the agent confirmed the claim against the log (`confirmed` only). The event's `timestamp` is still when the claim arrived |
| | `evidence` | What confirmed it: `daemon` (a line from `PrivilegesDaemon`), `extension` (the system extension's record of the change) or both (`confirmed` only) |
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
| | `instigator` | The process that added the user to `admin`, from SAP Privileges' system extension log (Privileges 2.6+, extension on, macOS 14+): `executable`, `signing_id`, `team_id` (empty for Apple's own), `platform_binary`, `pid`, `ppid`, `tty` (empty when not from a terminal) and `logged_at`, and `extension_verified`: `true` when the agent matched the entry to a running instance of the real extension (signed by SAP, running as root, started before it logged), `false` when it couldn't, for example an entry from before the agent first saw the extension. Absent when the extension logged nothing for this user in the last heartbeat interval plus 10 minutes |
| `admin.out_of_band_removed` | `trigger` | `heartbeat` |
| | `first_observed` | When the agent raised these rights, the same as its `admin.out_of_band` |
| | `grace_seconds` | Configured `OutOfBandGraceMinutes`, in seconds |
| | `observed_admin`, `verified` | `false`, `true`: the daemon removed the rights and confirmed it |
| `agent.health` | `admin_members` | Every human account that is admin right now |
| | `permanent_admins` | Configured standing admins |
| | `open_sessions` | `[{user, session_id, source}]` from the agent's ledger |
| | `queue_depth` | Events still waiting to be sent |
| | `privileges` | `installed`, `post_change_hook_configured`, `pass_reason_to_executable`, `expiration_interval_minutes` (only when MDM sets `ExpirationInterval`; `null` otherwise), `expiration_interval_max_minutes`, `enforce_privileges`, `system_extension_enabled`, `admin_budget_minutes` (`AdminBudget`, Privileges 2.7+; `null` when unset or 0), `expiry_capped` (MDM forces `ExpirationInterval` above 0, or, when MDM doesn't set `ExpirationInterval`, forces `ExpirationIntervalMax` above 0), `allow_privilege_renewal` and `post_change_action_on_grant_only` (`null` unless MDM sets them, as the user can change them otherwise), `auto_renewal_configured` (`AutoRenewalProcessPaths` names an app), `revoke_at_login`, `revoke_at_login_excluded_users`, `revoke_after_time_change`, `revoke_after_time_change_excluded_users` (`RevokePrivilegesAtLogin`, `RevokePrivilegesAfterSystemTimeChange` and their exclusion lists; `null` when unset) |
| | `integrity` | Each tamper check that applies on this Mac, check → passing (see `agent.tamper`) |
| | `persistence_unreadable` | Persistence locations that exist but the last snapshot couldn't read, such as a home folder privacy protection covers; empty when all were read. Missing before the first snapshot |
| `agent.tamper` | `check` | `launch_daemon`, `code_signature` (Altiward.app fails a strict signature check), `settings_managed` (one of the settings it checks comes from /Library/Preferences, not MDM), `privileges_tamper_protection` (Privileges installed: `EnableSystemExtension` is off, or SAP's system extension isn't running or isn't SAP's), `privileges_hook` (Privileges installed: its hook isn't Altiward's, or its checksum doesn't match Altiward's hook), `privileges_timer` (Privileges installed: someone logged in holds rights from a Privileges grant and their Privileges agent, which runs the timer, isn't running), `agent_version`, `privileges_blocked` (Privileges' system extension blocked an attempt to delete, rename, clone, add to or unload Privileges, one event per process and item each heartbeat), `grant_claim` (a claim from Privileges' hook was refused, or accepted without Privileges' log backing it; one event per claim), `grant_confirmation` (Privileges installed, and `OutOfBandEnforcement` or `ExpiryEnforcement` is `enforce`: the agent can't confirm grants against Privileges' log, or the extension has logged no record of a grant the daemon's line confirmed), `privileges_expiry_cap` (Privileges installed: MDM doesn't cap how long a grant lasts), `privileges_renewal` (Privileges installed and `ExpiryEnforcement` is `enforce`: MDM doesn't set `AllowPrivilegeRenewal` to false, or `AutoRenewalProcessPaths` names an app), `privileges_give_back_hook` (Privileges installed: MDM doesn't set `PostChangeActionOnGrantOnly` to false), `privileges_revoke_exclusions` (Privileges installed: `RevokePrivilegesAtLogin` or `RevokePrivilegesAfterSystemTimeChange` is on and its exclusion list leaves out an account in `PermanentAdmins`), `platform_sso_link` (a Mac account was linked to an account in Platform SSO, or its link was removed, at any time; registering for Platform SSO adds one) or `platform_sso_link_changed` (a Mac account's Platform SSO link moved from one account to another, or was added when the account was last linked to another, another Mac account has the same link, or someone held admin rights; at any time) |
| | `state` | `failed` (the check started failing, or fails the first time it runs), `restored` (it passes again), `retired` (it was failing and no longer applies, so its alert closes) or `detected` (a one-off: a downgrade, an attempt Privileges blocked, a claim the agent refused or couldn't confirm, or a Platform SSO link added, removed or changed) |
| | `problem` | What is wrong; for `retired`, why the check no longer applies (`SAP Privileges isn't installed now`, `ExpiryEnforcement isn't enforce now`); `null` when `restored` |
| | `previous_version`, `current_version` | The versions either side of a downgrade (`agent_version` only) |
| | `blocked_action`, `item` | What Privileges blocked (`DELETE`, `RENAME`, `CLONE`, `CREATE` or `EXEC`, which is unloading its launchd items) and the item's path (`privileges_blocked` only) |
| | `instigator` | The process that tried, as for `admin.out_of_band` without `logged_at`; `null` when the extension didn't say (`privileges_blocked` only) |
| | `extension_verified` | `true` when every attempt in the group was matched to a running instance of the real extension, as for `instigator` in `admin.out_of_band` (`privileges_blocked` only) |
| | `attempts`, `first_attempt`, `last_attempt` | How many times that process tried on that item since the last heartbeat, and when (`privileges_blocked` only) |
| | `truncated` | On the last of a heartbeat's 20 `privileges_blocked` events, how many more were left out; absent otherwise |
| | `user`, `claimed_state` | The account the claim named, and what it claimed: `admin` for a grant or renewal, `user` for a give-back (`grant_claim` only) |
| | `kind` | `grant`, `renewal` (a claim while the user's Privileges session was open and they were already admin) or `give_back` (`grant_claim` only) |
| | `outcome` | `refused`: nothing was recorded for the claim, and a session was neither opened nor renewed. Or `accepted_unconfirmed`: the claim was recorded, without Privileges' log backing it, because the log was lost on a Mac where the agent had read it before, or `OutOfBandEnforcement` is `alert` (`grant_claim` only) |
| | `reason` | Why, in words, the same as `problem`: the log doesn't confirm it; the caller is neither the user nor root; the log was available on this Mac before and isn't now; a grant claimed on a Mac without SAP Privileges; a grant claimed too long after Altiward raised the rights; or a give-back claimed while the user is still admin (`kind` `give_back`). Only grant claims refused for being too many (more than 5 in a minute from one caller) are logged on the Mac and not sent (`grant_claim` only) |
| | `caller_uid` | UID of the process that sent the claim; `null` when the daemon couldn't tell (`grant_claim` only) |
| | `user`, `previous_upn`, `upn` | The Mac account, the account it was linked to before and the one it is linked to now; `null` for none (`platform_sso_link` and `platform_sso_link_changed` only) |
| | `evidence_at`, `evidence_sources` | When the log line behind the claim was written, and which sources it came from (`daemon`, `extension`). Present only when the log did back the claim and it was refused anyway: a grant on a Mac without SAP Privileges (`grant_claim` only) |
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
| | `run_as` | The target user (`sudo` only; the agent doesn't send it yet) |
| | `count`, `last` | How many uses were grouped into this event since the last heartbeat, and the newest one's time (`single` only) |
| | `truncated` | On the last of a heartbeat's 20 `single` events, how many more groups were left out; absent otherwise |
| `persistence.detected` | `findings` | What is new or changed since the last snapshot, in a stable order. Each has `kind` and `change` (`added` or `modified`), plus fields by kind, below |
| | `since` | When the last snapshot was taken: the changes happened between then and `timestamp` |
| | `truncated` | Findings left out to keep the event small; `0` when all were sent |
| `agent.silent` | `state` | `silent` (the Mac stopped checking in) or `resumed` (it checked in again) |
| | `basis` | Why it was raised (`silent` only): `no_contact` (the Mac hasn't checked in for the tenant's limit) or `mdm_check_in` (with Intune connected, Intune heard from the Mac at least 2 hours after its last check-in with Altiward, so the Mac is on and online: the agent may have been removed or stopped). Left out by servers before 1.2.0, which raised only `no_contact` |
| | `last_seen_at` | The Mac's last check-in, by the server's clock (when it received the event, not the event's `timestamp`): before the silence for `silent`, the one that ended it for `resumed` |
| | `mdm_last_check_in` | With Intune connected, Intune's last check-in from the Mac, from the server's copy of Intune's Macs, and no later than the event's `timestamp`; left out when Intune doesn't list the Mac or hasn't heard from it (`silent` only, either basis). With `no_contact`, a check-in no later than `last_seen_at` says Intune hasn't heard from the Mac either, such as a closed laptop |
| | `admin_members` | The Mac's admin group at its newest health reading (macOS short names), so the alert says who was admin when it went quiet: sorted, without duplicates, empty names or names over 255 bytes, and at most 50; empty when nobody was (`silent` only) |
| | `admin_members_truncated` | How many names the cut to 50 left out; absent when none (`silent` only) |
| | `pending_device_id` | With Intune connected, the device ID of a key enrolled for the Mac since its last check-in that has waited for approval for more than a day; left out when there is none (`silent` only) |
| | `silent_after_seconds` | The tenant's limit when it was raised (`silent` only) |
| | `silent_since`, `alert_event_id` | The `last_seen_at` and event ID of the `silent` event this ends (`resumed` only) |
| `agent.enrollment` | `state` | `enrolled` (the Mac's first key, or its first after earlier ones were revoked with approval off if the Mac is not retired), `pending` (a new key waiting for an admin to approve it, always required for a retired Mac), `replaced` (a new key took the place of the previous one without approval), `rotated` (the Mac replaced its own key by proving it held the old one, so nothing waits for approval) or `rotated_key_used` (a key that rotation had already replaced signed a request: a copy of the old key may exist) |
| | `device_id` | The new key's device ID (a lower-case UUID), which names the credential; the stale key's for `rotated_key_used` |
| | `key_fingerprint` | Lower-case hex SHA-256 of the new key's public key (SPKI DER), 64 characters; the stale key's for `rotated_key_used`. The console's **Enrollments** shows its first 16 digits in capitals, in groups of four |
| | `key_storage` | Where the Mac said the private key is kept: `secure_enclave` or `software`; left out when the Mac didn't say |
| | `token` | The agent token the Mac enrolled with: `token:` and a short fingerprint of it, never the token (`enrolled`, `pending` and `replaced` only: a rotation doesn't use the token) |
| | `mdm_check` | With Intune connected, what Intune said about the device ID the Mac sent (its profile's `MDMDeviceID`), never the ID itself: `match` (Intune has the device, with the Mac's serial), `mismatch` (Intune has it under another serial, or on a platform other than macOS, so the ID is another Mac's or another device's: the key waits for approval whatever the settings), `unknown_id` (Intune has no such device, or one without a serial or operating system), `invalid_id` (not an Intune device ID, such as an unexpanded `{{deviceid}}` or the Mac's Entra device ID), `not_sent` (the profile sets no `MDMDeviceID`) or `unavailable` (Intune couldn't be asked in time). Left out without Intune (`enrolled`, `pending` and `replaced` only) |
| | `mdm_serial_known` | With Intune connected, whether Intune manages a Mac with this serial, from the server's copy of Intune's Macs or a lookup by serial; left out when that isn't known, such as before the first sync or when the lookup fails (`enrolled`, `pending` and `replaced` only) |
| | `previous_device_id`, `previous_key_storage` | The device ID and key storage of the credential that was active before the new key (`pending`, `replaced` and `rotated` only; always sent for `rotated`, and left out for the others when no credential was active, such as after it was revoked) |
| | `hardware_uuid_matches` | Whether the new key's hardware UUID is the previous credential's (sent with `previous_device_id`; always `true` for `rotated`) |
| | `rotated_to` | The device ID of the key that replaced the stale one (`rotated_key_used` only) |
| | `revoked_device_id` | The device ID of the key this event revoked, when it revoked one (`rotated_key_used` only) |
| `agent.admin_group` | `state` | `changed` (the group differs from the one last reported) or `snapshot` (the whole group: a Mac's first, and then once a day for each Mac that isn't retired, checked in during the last 24 hours and has a group reported) |
| | `members` | Everyone in the Mac's admin group at the reading (its `admin_members`), including anyone elevated at that moment |
| | `permanent_admins` | The reading's configured standing admins. It is not membership: a name on it may not be in the group, or not exist on the Mac |
| | `added` | The people who joined the group since the last report (`changed` only). Each has `name`, and `session_id` and `source` (`privileges` or `out_of_band`) of the matching entry in the reading's `open_sessions` when there is one. As a reading arrives, the link is kept only when the server holds that session, open, for the same Mac and person; the one-off backfill from readings stored before the upgrade doesn't check it |
| | `removed` | The names of the people who left it (`changed` only) |
| | `health_event_id` | The event ID of the `agent.health` reading this reports (a lower-case UUID) |
| | `as_of` | The reading's time by the Mac's clock. The event's `timestamp` is when the backend raised it |
| | `truncated` | People left out because a list holds at most 200 names, and names left out to keep the raised event under the 64 KiB detail limit; `0` when none |

`elevation.overdue` is sent at most once per session expiry (a renewal re-arms it) and
leaves the session open. `elevation.expired_enforced` ends it.

`admin.out_of_band_removed` ends an out-of-band session; the agent sends it only when
`OutOfBandEnforcement` is `enforce`.

`agent.tamper` is sent when a check changes, not on every heartbeat: the agent keeps each
check's last result, so a restart doesn't repeat an alert. A check that stops applying
sends `retired` if it was failing, and is dropped without an event if it was passing.

`agent.tamper` with check `grant_claim` is sent when a claim from Privileges' hook is refused,
whatever the reason except a caller sending too many, or accepted without Privileges' log backing it. It is a one-off (`detected`), never
`restored`. With Privileges' log available, a grant claim is held for up to a minute, and its
event is sent when the claim is confirmed or refused. While the log is available, a renewal claim through the hook renews the
session only when fresh log evidence confirms it. Otherwise, once the confirmation window has
passed (or at once if the log is lost), it is refused in every mode, reported with kind
`renewal`, and the expiry doesn't move: a real Privileges renewal sends no claim.
`elevation.granted` carries `privileges_log` when the agent checked the claim.

`admin.permanent_use` records a use of an account in `PermanentAdmins`. Its `user` is that
account; it has no `session_id` and no `elevation`, so it is never a session. A sign-in sends
`started` and later `ended`, paired by `use_id`. A prompt and a screen sharing
connection send `single`: one event per grouped use, with `count` and `last`. The agent
sends `console`, `terminal` and `ssh` sign-ins, `prompt` and `screen_sharing`. It doesn't send
`sudo`, `su` or an SSH use seen only in the log: macOS keeps no log line for them, so they
wait for Apple's Endpoint Security entitlement. The server accepts them.

Released agents' events are frozen in [`compat/`](compat/), one directory per supported
agent minor release, and the server must keep accepting all of them.

`agent.silent` is raised by the backend's monitor, not the agent. Its `timestamp` is when
the backend raised it and `device` is the Mac's last known identity and versions. It
doesn't count as a check-in. Each silence is raised once: the event ID is a name-based
UUID of the tenant, serial and what it reports, the same on either basis. A Mac raised on
`mdm_check_in` isn't raised again when it reaches the tenant's limit. Retired Macs (an
admin revoked the last key) don't alert. A Mac whose key a stale-key contest revoked isn't
retired, so it does.

With Intune connected, the `mdm_check_in` basis applies only to the Intune tenant's Macs
whose agent has ever reported version 1.2.0 or later (the first that checks in at least
hourly), or a version the server can't read, matched to Intune by serial number as the Mac
reports it (a serial with spaces around it or in lower case never matches). It applies
only while the Mac has been quiet for less than a day; a longer silence waits for the
tenant's limit. It waits 2 hours and 10 minutes after the server starts, so that Intune's
check-ins from during an outage don't trip every Mac. A Mac with a key enrolled since its
last check-in and waiting for approval isn't raised on it, since a pending key can't check
in: the wait lasts a day from the oldest such key, longer than the basis applies. It is
reported at the tenant's limit, naming that key once it has waited a day. If more than the larger of 5 and a fifth of the
Macs Intune lists meet the rule at once, counting those already raised on it, none is
raised on it: Altiward is then probably what the Macs can't reach. The server logs a
warning, and `GET /v1/mdm` shows when this last happened (`silence_held_at`) and for how
many Macs (`silence_held`). A Mac Altiward last heard from before that time is never raised
on `mdm_check_in`, even once fewer Macs meet the rule: it is reported when it reaches the
tenant's limit. Macs that check in after it are raised early as before.

`agent.enrollment` is raised by the backend when a Mac enrols a key, not by the agent.
Its `timestamp` is when the backend raised it, and `device` is what the Mac said when it
enrolled, with an empty `os_version`. It doesn't count as a check-in, and it doesn't add a
Mac to the fleet: a Mac the server hasn't heard from yet has no entry until it reports.
Each key is reported once: the event ID is a name-based UUID of the tenant and `device_id`.
A `rotated_key_used` event has a random ID, and its `device_id` is the stale key's. For it, `device.agent_version` is the version that sent the stale request.

`agent.admin_group` is raised by the backend, not the agent, so the SIEM keeps who was in a
Mac's admin group after the health readings that recorded it expire. Its `timestamp` is when
the backend raised it, and `device` is the Mac's last known identity and versions. It doesn't
count as a check-in. It is a record, not a detection: `admin.out_of_band` and the elevation
events raise the findings. Only `members` is the group; a change to `permanent_admins` alone
raises nothing. Duplicates and over-long names are dropped. Lists are cut to 200 names, and
further if the event would pass the 64 KiB detail limit, and `truncated` counts the names
cut.

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
