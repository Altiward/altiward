# Changelog

Release notes for the Altiward server and the Mac agent, newest first. Releases are
published on GitHub, and each release's section
is its notes.

Each release has one section headed `## Server X.Y.Z - YYYY-MM-DD` or
`## Agent X.Y.Z - YYYY-MM-DD`. Write `unreleased` instead of the date until the day it
ships: the release workflows refuse a version whose section is missing or unreleased.
Every section has the four headings below, with "None." under any that don't apply.

## Agent 1.0.0 - 2026-10-27

### Upgrade order

Upgrade the server first. An agent that can rotate its key, on a server that can't, keeps
its key and asks again a day later. Anything between the Macs and the server, such as a
firewall or TLS-inspecting proxy, must pass the whole of `/v1/agent/` to the server
unaltered, including the new `/v1/agent/rotate`.

### Breaking changes

None.

### Security

- The agent can replace its device key with a new one (key rotation), which moves a key
  kept in a file into the Secure Enclave. It sends the new public key with a proof signed
  by the new key, in a request signed by the old one. Until the server's answer is known,
  it keeps both keys in `agent.sqlite` and sends nothing else signed by the old key, in
  the daemon or in a command run beside it, so a lost answer, a restart, sleep or a busy
  store never makes a Mac look like a second holder of its own key. Once a rotate request
  may have reached the server, only the server's refusal, with its code, makes the agent
  give up the rotation, so a proxy's block page or throttle can't either. A command run
  while the daemon is rotating says so and changes nothing.

### Changes

- The daemon and commands share the server clock offset they learn, so a command run on a
  Mac whose clock is wrong no longer needs a round trip to correct it.
- The daemon now rotates the device key. A Mac with a Secure Enclave moves a file key into
  it, once the key has signed a request successfully since the daemon started. A Mac
  without one replaces its file key every 30 days, counted from when the key was made (a
  key with no recorded date starts counting when the agent first sees it). A Secure Enclave
  key never rotates. The daemon checks between long polls and at least hourly, starting
  5 to 65 minutes after it starts, and `altiward-agent status` shows a rotation still in
  progress. A process counts as the daemon only when launchd started it or it has its own
  data directory, so a `run` typed in a Terminal on a managed Mac is a command.
- `altiward-agent status` shows the device key's fingerprint, as **Enrollments** shows it,
  so you can tell which pending key is the Mac's.

## Server 1.0.0 - 2026-10-27

### Upgrade order

Upgrade the server before the agents: an agent 1.0 on an older server keeps its key and
asks to rotate it again a day later. The server adds three columns and an index to the
device credentials table on first start. Don't run 0.9 and 1.0 servers on one database: a
0.9 server doesn't know the two new `agent.enrollment` states. One rolled back to 0.9 still
refuses the keys rotation replaced, but raises no alert when one is used again, and
its diagnostics list migration 0006 as unknown. After restoring a backup, Macs whose key
rotated since it was taken enrol again and wait for approval.

### Breaking changes

None.

### Security

- Revoking a key that an admin approved at the same moment could leave the key active. The
  revoke now always wins.
- A key replaced by rotation stops working. If it is used again within 30 days of being
  replaced, two holders share the Mac's identity, so the server also revokes the Mac's
  current key and the Mac enrols again (waiting for approval when that is on). A copied key
  can then cause one visible disruption, not take the Mac's place. Someone holding a copy
  of a key replaced in the last 30 days can cause that disruption once, with or without the
  enrolment token.

### Changes

- The supported agent minor releases are 0.9 and 1.0. The frozen compatibility fixtures
  retain both, and the console flags agents older than 0.9 as out of support.
- A Mac can replace its key with one it proves it holds: `POST /v1/agent/rotate` replaces
  the key that signs the request with the one in its body, after checking a proof signed
  by the new key. The new key is active at once, with the Mac's serial and hardware UUID,
  and the old key is revoked in the same step. A key must have been active for 24 hours
  first, and a key kept in the Secure Enclave is never replaced. Sending the same request
  again answers with the key it made.
- A rotation raises an `agent.enrollment` event with state `rotated`. A key that rotation
  replaced and that signs a request again raises one with state `rotated_key_used`: a
  High alert that names the key the server revoked as a result, if any. It is raised at
  most once a day for each key, unless that use revoked a key. A request signed just before the
  rotation and arriving within a minute of it raises nothing.
- Enrollments shows a key that rotation replaced as Rotated, not Revoked, with the date and a
  link to the key in use, and a key made by rotation says which key it came from. Rotated
  keys have a filter of their own, and Revoked lists only keys that were revoked. The
  inspector shows each key's device ID, which `altiward-agent status` prints on the Mac.
  Revoking a rotated key answers 409 `credential_rotated` and names the key in use
  (`current_device_id`), which is the one to revoke. For a key kept in a file, the console now
  says that agent 1.0 moves it into the Secure Enclave by itself or, on a Mac without one,
  replaces it every 30 days, instead of suggesting a revoke.

## Agent 0.9.0 - 2026-10-27

### Upgrade order

Upgrade the server to 0.9.0 first. Deploy this release's Privileges hook checksum with
its package, as for every agent upgrade.

### Breaking changes

None.

### Security

None.

### Changes

None.

## Server 0.9.0 - 2026-10-27

### Upgrade order

Upgrade the server before the agents. The new credential index is built on first start;
large credential histories may take longer to migrate.

### Breaking changes

None.

### Security

None.

### Changes

- The supported agent minor releases are 0.8 and 0.9. The frozen compatibility fixtures
  retain both, and the console flags agents older than 0.8 as out of support.

- Bounded, fixture-seeded Go fuzz campaigns exercise event and command-result decoding,
  signed requests and enrolment parsing in CI, including signature integrity and enrolment
  retry idempotence.
- CEF enrolment events include the token fingerprint as `suser` and the device credential
  ID as `cs5` (`target`), so SIEM users can join them with approvals and revocations.
  Sentinel's `UserName` also includes the enrolment token fingerprint. A permanent admin
  account's use on another user's session carries that user as `suser`, the OCSF actor.
- Enrolment limit checks no longer read the organisation's whole credential history: a
  new index covers each Mac's own keys, and the count of new Macs reads only the last
  hour's enrolments.
- Enrolment limit refusals log a warning once per tenant and limit window per server
  instance, to limit log noise during a storm. The next warning counts the refusals in
  between that weren't logged, as `not_logged`.
- Enrollments loads and polls Fleet evidence only while a pending key is selected, and
  hides the last check-in if the latest refresh fails.
- Token rotation guidance covers a leaked token exhausting the enrolment limits.
- Each key records the enrolment token it enrolled with, by its fingerprint. **Enrollments**
  shows it, and searching for it finds every key one token enrolled, so a leaked token's
  keys can be found and revoked. Keys enrolled before 0.9.0 show "Not recorded". The
  install guide suggests one agent token per group of Macs.
- **Approve every new Mac**, in Settings, off by default: a Mac's first key waits for
  approval too, so the shared enrolment token can't add a Mac or take a real Mac's serial
  before it enrols. It costs one approval for each Mac rolled out.

## Agent 0.8.0 - 2026-10-26

### Upgrade order

Deploy this release's `corp.sap.privileges.plist` keys to your Privileges profile with the
package: its `PostChangeExecutableChecksum` is this build's hook. With the old checksum,
Privileges stops running the hook and Altiward raises "SAP Privileges no longer reports to
Altiward". Upgrade the server to 0.8.0 first, so it can tell an agent that its key belongs
to another Mac.

### Breaking changes

None.

### Security

- Hook claims are bound to the authenticated caller before log fallbacks, permanent-admin
  handling or queuing. Unknown accounts and callers are refused, and held claims are
  checked again before they can change a session. Root remains an explicit authorised
  caller for administrative operations.
- A give-back claim cannot close an open session while the account is still an admin.
  The agent retains the original expiry and retries membership confirmation on its next
  heartbeat, so a contradictory claim cannot bypass timed enforcement.
- The agent stores its Mac's serial and hardware UUID with its device key. A key found on
  a different Mac, such as a store copied by Migration Assistant, a clone or a restore,
  is dropped and the Mac enrols afresh instead of signing as the first Mac. A key stored
  by an earlier agent is given this Mac's identity and stays enrolled. If the Mac won't
  report its serial or hardware UUID at the time, the agent keeps its key and checks on a
  later run.
- When the server rejects this Mac's own events because the agent's key belongs to another
  Mac, the agent keeps the events, drops the key and enrols again, instead of deleting
  them. Events that name another Mac are still deleted. This needs Server 0.8.0, which
  says why it rejected them.

### Changes

- An empty file the persistence check reads, such as an empty `~/.ssh/authorized_keys`,
  no longer counts as unreadable, so it doesn't mark the Mac **Partly checked** in Fleet
  (#115).
- When the server's enrolment limits refuse the Mac (HTTP 429), the agent doesn't ask again
  until the time `Retry-After` gives, or for an hour when it gives none, and never waits
  more than a day. Earlier agents asked about once a minute. The wait is kept in memory,
  so an agent that restarts asks once more.

## Server 0.8.0 - 2026-10-26

### Upgrade order

Upgrade the server before the agents.

On the first start after this upgrade, **Approve Macs that enrol again** is enabled for
all existing tenants, including those where it was off. Current credentials and other
settings stay as they are. A replacement key waits for approval, including after the old
key was revoked. An admin who needs automatic replacement must explicitly turn the
setting off after upgrading.

### Breaking changes

None.

### Security

- Re-enrolment requires approval by default. Missing or null approval flags in stored
  settings and API updates keep approval on; only an explicit `false` opts out. First
  enrolments still trust the shared token and need checking against independent inventory.
- Events cannot alter a session owned by another Mac or local account. A conflicting
  batch is refused without changing events, session or device state, or pending exports.
- Splunk exports complete only after a valid explicit accepted HEC acknowledgement.
  Redirects and ambiguous, invalid or incomplete responses keep the batch queued for retry.
- Compose and Azure use the same digest-pinned Caddy 2.11.7 proxy rebuilt with patched
  Go and HTTP/2 dependencies. Each server release verifies and scans both platform
  binaries before publishing the exact reviewed image.
- The server reports each new enrolment to your SIEM as an `agent.enrollment` event, in the
  state `enrolled`, `pending` (a new key waiting for approval) or `replaced`. It carries the
  Mac, the key's device ID, SHA-256 fingerprint and storage, the enrolment token's name and,
  when a key was active before, that key and whether the hardware UUID matched.
- The enrolment token can no longer add Macs or keys without end. Each organisation may
  add 1000 Macs it hasn't enrolled before in an hour, and one Mac may enrol 5 keys in 24
  hours; the server answers 429 with `Retry-After` and logs `enrolment rate limited`. Agent
  0.8.0 waits that long before it asks again; earlier agents ask about once a minute. A Mac
  sending a key that is already enrolled is never refused. Set
  `ALTIWARD_ENROLL_NEW_MACS_PER_HOUR` and `ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY` in `.env`
  (`0` turns one off), or on the Azure container app; raise the first before enrolling more
  than 1000 Macs in an hour.
- A new key whose hardware UUID differs from the Mac's active key waits for approval even
  when **Approve Macs that enrol again** is off, and its `agent.enrollment` event shows
  `hardware_uuid_matches` as false. The UUID is the agent's own claim, so this catches a key
  made on another Mac, not someone who sets it by hand.

### Changes

- Settings is split into tabs, each at its own address: **General** (`/settings`:
  enrollment, alerts, appearance), **SIEM export** (`/settings/siem`), and for admins
  **Sign-ins** (`/settings/sign-ins`) and **Updates** (`/settings/updates`). Overview's SIEM
  tile opens SIEM export.
- **Settings › SIEM export** shows how to connect each SIEM that isn't connected yet (#37):
  lines to copy and its setup guide. On Docker Compose they're `.env` lines, each optional
  setting commented out under what it does; on Azure Container Apps, `az containerapp`
  commands for the app, with secrets kept as app secrets and Sentinel signing in as the
  app's managed identity. It shows placeholders only. SIEM settings stay in the server's
  environment, so changing where events go still takes access to the server, not just the
  console.
- The install guide runs the server from a directory of its own, such as `/opt/altiward`,
  so it doesn't stay in one named for the release first installed. It gives the commands
  to download a release and make the tokens, a nightly backup, and a new Enforcement
  section for `ExpiryEnforcement` and `OutOfBandEnforcement`, which step 2 now points to
  (#111).
- The console's sidebar stays in view on long pages such as Overview, so who is signed
  in, **Sign out** and the server version show on every page (#112).
- A rejected event whose `device.serial` isn't the signing Mac's carries `code`:
  `device_mismatch` in the ingest response. Other rejections have no `code`.
- **Enrollments** shows, for a key waiting for approval, when the Mac last checked in with
  its current key, and warns when the new key reports a different hardware UUID.

## Agent 0.5.0 - 2026-10-25

### Upgrade order

Add this release's `corp.sap.privileges.plist` keys to your Privileges profile with the
package, as for every release. It now also sets `ExpirationIntervalMax` (60 minutes: change
it to your policy), `AllowPrivilegeRenewal` and `PostChangeActionOnGrantOnly`, so the new
checks pass. Upgrade the server to 0.6.0 first: an older server exports the four new checks
to the SIEM as high severity findings titled only by their names, and the console shows them
unlabelled.

### Breaking changes

None.

### Security

- A caller can send at most 5 give-back claims a minute through the hook that the agent
  records or reports (closes #96). Before, there was no limit: anyone could run
  `altiward-hook` by hand in a loop and queue an event for each run, a refused give-back
  in `OutOfBandEnforcement` `enforce` mode, a give-back from another user's account, or a
  give-back that ended no session, and fill the outbox and the SIEM. Past the allowance, a
  give-back that ends an open session is still recorded, so a real give-back is never lost,
  and any other is logged on the Mac and not sent.

### Changes

- A grant's expiry follows `ExpirationInterval` only when MDM sets it. One set anywhere else,
  such as `/Library/Preferences`, is only a default the user's own Privileges settings
  override, so the agent now takes the expiry from Privileges' timer, within
  `ExpirationIntervalMax`. Before, an `ExpirationInterval` of 0 there meant the agent
  recorded no expiry and `ExpiryEnforcement` never acted, while Privileges ended the rights
  at the maximum. `agent.health` reports `expiration_interval_minutes` only when MDM sets it.
- A renewal in SAP Privileges now moves the session's expiry (closes #90). Privileges sends
  no hook claim for one and records it only as a line from `PrivilegesAgent`, so with
  `ExpiryEnforcement` on `enforce` the agent removed renewed rights at the original expiry.
  At each heartbeat, before expiry is enforced, the agent reads those lines and sends an
  `elevation.granted` (`renewed`, `trigger` `privileges_renewal`) with the new expiry: the
  renewal's time plus its minutes, capped by `ExpirationIntervalMax`. `PrivilegesAgent` runs
  as the user, so a line counts only when the log recorded SAP's agent executable for it
  and the process is SAP's signed agent, running as that user and started before the line.
  A line whose process has gone can't be checked and is ignored. While MDM sets
  `AllowPrivilegeRenewal` to `false`, the lines aren't read, which stays the recommendation.
  `docs/data-handling.md` lists what is read.
- The agent answers a hook claim at once (#91). Without SAP Privileges' log, or for
  a permanent admin, a grant claim waited inside the hook's call while the agent read
  Privileges' timer, up to 18 s, and sometimes for the store while the agent read the
  unified log, so the hook gave up after 5 s with "Could not reach altiward-agent" and the
  untracked-admin check could raise the grant as `admin.out_of_band` first. Now such a
  claim is held, like a claim waiting for Privileges' log, and recorded straight after the
  hook has its answer; the log is read outside the store's lock. With a fixed
  `ExpirationInterval` nothing changes, as no timer is read. On a Mac without the log and
  without a fixed `ExpirationInterval`, the hook now logs "Sent admin for" for a grant claim
  the agent then refuses; the refusal is still reported as `grant_claim`. When answering a
  claim still takes more than a second, the agent logs a notice saying how long it spent on
  each step, so a slow Mac names the cause.
- New integrity checks for the SAP Privileges settings Altiward relies on (#92). Privileges
  lets users change any setting its profile doesn't set, so only values MDM sets count:
  - `privileges_expiry_cap`: MDM doesn't cap how long a grant lasts (`ExpirationIntervalMax`,
    or a fixed `ExpirationInterval`), so a user can choose to keep admin rights with no
    expiry.
  - `privileges_renewal`, while `ExpiryEnforcement` is `enforce`: MDM doesn't set
    `AllowPrivilegeRenewal` to `false`, or `AutoRenewalProcessPaths` names an app. A renewal
    reaches Altiward only from a log line a user's process writes (see below), so
    enforcement may still remove renewed rights at the original expiry.
  - `privileges_give_back_hook`: MDM doesn't set `PostChangeActionOnGrantOnly` to `false`, so
    a user can stop Privileges running Altiward's hook when rights are given back.
  - `privileges_revoke_exclusions`: `RevokePrivilegesAtLogin` or
    `RevokePrivilegesAfterSystemTimeChange` is on and its exclusion list leaves out an
    account in `PermanentAdmins`, which Privileges then makes a standard user.
- `corp.sap.privileges.plist` sets `ExpirationIntervalMax`, `AllowPrivilegeRenewal` (`false`)
  and `PostChangeActionOnGrantOnly` (`false`), and suggests the two revoke settings in a
  comment, with exclusion lists to fill in. `docs/install.md` explains each.
- `agent.health`'s `privileges` section gains `expiry_capped`, `allow_privilege_renewal`,
  `auto_renewal_configured`, `post_change_action_on_grant_only`, `revoke_at_login`,
  `revoke_at_login_excluded_users`, `revoke_after_time_change` and
  `revoke_after_time_change_excluded_users`. `docs/data-handling.md` lists them.

## Server 0.6.0 - 2026-10-25

### Upgrade order

None needed beyond the usual: upgrade the server before the agents.

### Breaking changes

None.

### Security

None.

### Changes

- The SIEM export titles the four new Privileges settings checks (`privileges_expiry_cap`,
  `privileges_renewal`, `privileges_give_back_hook` and `privileges_revoke_exclusions`), all
  medium severity. Each closes when it passes.
- The console labels the new checks (Privileges expiry cap, Privileges renewals off,
  Privileges reports give-backs, Privileges spares permanent admins), and a Mac's
  **Expires after** shows the cap on what a user picks (`Up to 60 min`), and says when MDM
  doesn't set it.
- A session's timeline notes a renewal read from Privileges' log as "Renewed in
  Privileges".
- The console says why a value is missing (#105): "Not set" for a
  Privileges setting MDM doesn't set, "Not reported" for what an older agent doesn't send,
  "None given" for a session without a reason, "Not yet" for a session still open or an
  enrollment not yet activated, "No expiry known", "Waiting to be sent" and "Nothing to do"
  for commands, and "Unknown" otherwise. A screen reader reads the word.

## Agent 0.4.0 - 2026-10-25

### Upgrade order

Deploy this release's `corp.sap.privileges.plist` keys to your Privileges profile with the
package: its `PostChangeExecutableChecksum` is this build's hook. With the old checksum,
Privileges stops running the hook and Altiward raises "SAP Privileges no longer reports to
Altiward".

Upgrade the server to 0.5.0 first, for the console's labels.

### Breaking changes

None.

### Security

- A grant claimed through the hook now counts only when SAP Privileges' own log backs it
  (closes #80). Anyone who already held admin rights could run `altiward-hook` by hand to
  open a Privileges session: just before the agent raised their rights, after removing
  themselves from `admin` and claiming a give-back, or by claiming again every few minutes
  to renew the session for ever, which defeated `ExpiryEnforcement`. The agent now reads
  the lines `PrivilegesDaemon` writes when it grants admin rights, and the records
  Privileges' system extension keeps, and checks the code signature, user and start time
  of the process that logged each. A grant claim waits up to a minute for a line that backs
  it, logged from two minutes before the claim arrived. In `OutOfBandEnforcement` `enforce`
  mode a claim the log doesn't confirm is refused, reported, and the rights are removed
  after the grace period, counted from when the agent first saw them. In `alert` mode it is
  accepted, marked not confirmed and reported. A claim through the hook renews a Privileges
  session only when fresh log evidence confirms it; otherwise it is refused and the expiry
  doesn't move. A claim from a process of another user, who isn't root, is refused, and a
  caller is limited to 5 grant claims a minute. Full protection needs Privileges 2.6 or
  later with its system extension on, on macOS 14 or later. Without it the agent works as
  before, marks the grant as not checked, and fails a new check. It is not a boundary
  against root: someone with root can still forge the log.

### Changes

- New `agent.tamper` event, check `grant_claim`, state `detected`: a claim from Privileges'
  hook that the agent refused, or accepted without Privileges' log backing it. Every
  refusal is reported, the earlier ones too (a grant claimed on a Mac without SAP Privileges
  or long after the rights appeared, and a give-back while the user is still admin), except
  a caller sending more than 5 grant claims a minute, which is only logged on the Mac. It
  carries the account, what was claimed, whether it was a grant, a renewal or a give-back
  (`kind`), the `outcome` (`refused` or `accepted_unconfirmed`), the reason, the UID of the
  caller and, when a log line was found, `evidence_at` and `evidence_sources`.
- New integrity check `grant_confirmation`, shown with the Mac's other checks and in
  `agent.health`: it fails while the agent can't confirm Privileges grants, and says why
  (Privileges older than 2.6, no verified system extension running, macOS older than 14, or
  the extension logged no record of a grant the daemon's line confirmed). It is left out
  unless `OutOfBandEnforcement` or `ExpiryEnforcement` is `enforce` and Privileges is
  installed.
- `elevation.granted` gains `detail.privileges_log` (`confirmed`, `not_confirmed` or
  `unavailable`), `detail.confirmed_at` and `detail.evidence` (`daemon`, `extension`).
  The expiry of a confirmed grant counts from when Privileges logged it, not from when the
  claim arrived. A confirmed grant replaces an out-of-band session however long ago the
  agent raised the rights; before, a real grant arriving more than a minute later was
  refused and the rights removed.
- `instigator` on `admin.out_of_band`, and `agent.tamper` events with check
  `privileges_blocked`, gain `extension_verified`: whether the agent matched the log entry
  to the real extension. The entry is sent either way.
- The agent keeps a held grant claim on the Mac (account, reason, caller UID and time)
  until it is confirmed or refused, and remembers the process ID and start time of the
  extensions it has verified. `docs/data-handling.md` lists both.
- A real renewal in Privileges sends no claim, so Altiward doesn't see it (#90). Until
  that is fixed, with `ExpiryEnforcement` on `enforce`, set Privileges' `AllowPrivilegeRenewal`
  to `false` (#92).
- When the agent refuses a claim, for example a grant claimed long after the rights
  appeared in `enforce` mode, `altiward-hook` now logs "altiward-agent refused the claim"
  with the reason and exits with 77 (`EX_NOPERM`). It used to log "Could not reach
  altiward-agent", which now only means the agent didn't answer (exit 69,
  `EX_UNAVAILABLE`). When the agent takes the claim, the hook logs "Sent admin for <user>"
  (or "Sent user ..."), not "Recorded ...": the agent may hold a grant claim until
  Privileges' log confirms it.
- The *Privileges tamper protection* check now also fails when `EnableSystemExtension` is
  on but SAP's system extension isn't running, or isn't SAP's (#93). It used to read the
  setting only, so a Mac whose extension was never approved, or was stopped, passed.

## Server 0.5.0 - 2026-10-25

### Upgrade order

None needed beyond the usual: upgrade the server before the agents. Agent 0.4.0's new
events and fields work with Server 0.4.0 too, but the console shows the new checks by their
raw names until you upgrade.

### Breaking changes

None.

### Security

None.

### Changes

- The SIEM export titles the two new `agent.tamper` checks: `grant_claim` (a high severity
  finding for each claim refused or not confirmed, analytic `altiward.tamper.grant_claim`)
  and `grant_confirmation` (medium severity while it fails, closed when it passes).
- The console labels the new checks (Grant confirmation, Grant claim not confirmed) and a
  session's timeline says whether Privileges' own log confirmed a grant.

## Agent 0.3.0 - 2026-10-24

### Upgrade order

Upgrade the server to 0.4.0 first: older servers reject `admin.permanent_use`, and the
agent drops events the server rejects. Update altiward-siem to 0.4.0 too.

### Breaking changes

None.

### Security

None.

### Changes

- The agent records each use of an account in `PermanentAdmins`, as `admin.permanent_use`.
  It is always on for every account listed, needs no new setting, and is evidence, not an
  alert: **Admins now** and the alerts don't change.
  - Sign-ins at the Mac (login window, fast user switching), in Terminal and over
    interactive SSH, from macOS's sign-in records. A `started` event follows within about
    15 seconds, and an `ended` event at sign-out with both times. A sign-in shorter than
    that is reported by the next heartbeat, and one while the agent was stopped when it
    starts, up to a day back. SSH records the address it came from. A Terminal tab opened
    while the account is signed in at the Mac is part of that sign-in, not a use of its
    own. A sign-in still open when the Mac crashed ends at the next boot.
  - Prompt approvals: a permanent admin's name and password typed into an admin prompt on
    another user's session. It records whose session, the right, and the app that asked,
    when the log names it.
  - Screen sharing: one event for each connection that signs in as the account, with the
    viewer's address. The name the viewer types can be the short name or the account's
    full name, in any case; the event always names the short name. A viewer who gets the
    password wrong isn't a use.
  - Prompts and screen sharing are read from the unified log each heartbeat. macOS keeps
    no log line for `sudo`, `su`, or SSH file copies and one-off commands that open no
    terminal (`scp`, `ssh host command`), so they aren't recorded until Apple grants the
    Endpoint Security entitlement.
- Prompts and screen sharing that differ only in time are one event, with a count and the
  time of the last: a script that approves 300 prompts within one heartbeat sends one.
  Each heartbeat sends at most 20 such events, and the last says how many more groups it
  left out.
- New command: `sudo altiward-agent permanent-uses [HOURS]` prints what the agent reads
  about permanent admins (default 24 hours; run as root).
- `docs/data-handling.md` lists what the agent collects. The SIEM gets every event the
  agent sends. For the console, the server keeps each Mac's open sign-ins and its newest
  20 other uses.

## Server 0.4.0 - 2026-10-24

### Upgrade order

Upgrade before Agent 0.3.0. Update altiward-siem to 0.4.0. An older server rejects
`admin.permanent_use`, which Agent 0.3.0 sends, and the agent deletes events the server
rejects.

### Breaking changes

Agent 0.1 is no longer supported: support covers the last two agent minors, now 0.2 and
0.3. The console marks Macs still running agent 0.1.x. Update them to Agent 0.3.0.

### Security

None.

### Changes

- The server accepts, stores, shows and exports `admin.permanent_use`, which Agent 0.3.0
  sends when someone uses a permanent admin account (`PermanentAdmins`). It exports it
  as an OCSF Authentication record. **Fleet** keeps each Mac's open sign-ins (up to 20)
  and its newest 20 other uses, and shows up to 10 under **Permanent admins** in the
  Mac's details, open sign-ins first: who, how (signed in at the Mac, in Terminal or over
  SSH, approved a prompt, shared the screen), from where, and whether the sign-in is still
  open. The SIEM gets every event the agent sends. Agent 0.3.0 sends screen sharing; the
  server and console also accept and show `sudo` and `su`, for a later agent that can
  record them, which needs Apple's Endpoint Security entitlement.
  `docs/data-handling.md` lists what is kept and sent.

## Agent 0.2.0 - 2026-10-24

### Upgrade order

Upgrade the server to 0.3.0 before you set `OutOfBandEnforcement` to `enforce`. An older
server rejects `admin.out_of_band_removed`, and the session would stay open in the console.
Update altiward-siem to 0.3.0 too. In `alert` mode, the default, this agent works with
server 0.2.0. A server before 0.3.0 ignores where the Mac says its key is kept.

### Breaking changes

- On a Mac whose key is in the Secure Enclave, `altiward-agent heartbeat`, `flush`,
  `commands` and `simulate-hook` run by hand no longer send: only the daemon can use the
  key, and it sends within a minute.
- An agent older than 0.2.0 installed over this one can't use a Secure Enclave key, so the
  Mac enrolls again with a file key, which waits for approval if **Approve Macs that
  enroll again** is on. That makes going back to 0.1.1 a way out if the Secure Enclave
  ever misbehaves.

### Security

- A Mac with a Secure Enclave (Apple silicon, or an Intel Mac with a T2 chip) now makes
  its key there when it enrolls. Someone given admin rights could copy a key kept in a
  file and later sign as that Mac from anywhere; a copy of a Secure Enclave key is no use
  off the Mac. Macs already enrolled keep their file key until they enroll again: revoke
  a Mac's key in **Enrollments** to move it. The agent tells the server where its key is
  kept, and `altiward-agent status` shows it.

### Changes

- New setting `OutOfBandEnforcement`. `alert`, the default, raises `admin.out_of_band`
  only, as before. With `enforce`, an account whose admin rights nobody granted loses
  them once they have lasted `OutOfBandGraceMinutes` (default 5, minimum 1) since the agent
  raised them: the next heartbeat removes it from `admin` and sends
  `admin.out_of_band_removed`, so it acts up to `HeartbeatInterval` late. Any other value
  means `alert`.
- **Check before you turn on `enforce`.** The agent counts as a human admin any member of
  `admin` with a UID of 500 or more, and any direct member of `admin` other than `root` and
  `_` accounts, hidden ones included. With `enforce`, an admin account your MDM manages, such as
  the LAPS account or a hidden management account with a low UID, loses its rights within
  minutes unless it is in `PermanentAdmins`. Without SAP Privileges, that is every admin who
  isn't a permanent admin. Before turning it on, check **Admins now** for the rows marked
  **Without a grant** on the Macs in scope, and pilot it on a small group first.
- Safeguards in `enforce` mode: the agent never removes a permanent admin, and keeps at
  least one standing admin: a permanent admin, or else the account nobody granted it has
  seen longest (of accounts raised at the same moment, the one whose short name sorts
  last). Someone holding admin through a Privileges grant doesn't count, and nor do admins
  still in their grace period or not yet raised. It pauses all removals while the
  `privileges_hook` tamper check (**Privileges reports to Altiward**) fails, because then
  every Privileges grant would look like rights nobody granted. That doesn't cover a
  `HookCodeRequirement` that doesn't match the hook: check it names the right Team ID
  before turning `enforce` on. A kept, paused or failed removal leaves the finding open,
  retries at every heartbeat and is logged on the Mac. A Privileges grant whose hook never
  reached the agent looks like rights nobody granted and can be removed; the person can
  request again. A Privileges grant claimed on a Mac without SAP Privileges or more than a
  minute after the agent raised the rights, and a give-back claimed while the account is
  still an admin, are refused and logged on the Mac, and the rights are still removed: a
  real grant's hook arrives well within that minute. Running the hook by hand can still
  keep the rights in two ways: claiming a grant before the agent raises them (in the 30
  seconds or so before it does, or between heartbeats), or, with root, leaving `admin`,
  giving the rights back, rejoining and claiming a grant. A later release will accept a
  grant claim in `enforce` mode only when Privileges' own log shows Privileges added the
  user.
- `OutOfBandEnforcement` and `OutOfBandGraceMinutes` are covered by the tamper check:
  `agent.tamper` reports either set outside MDM (`settings_managed`). Changing either
  restarts the agent. `docs/data-handling.md` lists what the agent collects.
- After the server has been unreachable, a Mac sends its waiting events as soon as the
  server answers its command poll, instead of waiting out its retry backoff, which grows to
  an hour during a long outage. Before, only a network change on the Mac cut the wait
  short. A server that answered with an error is still retried with backoff.

## Server 0.3.0 - 2026-10-24

### Upgrade order

Update altiward-siem to 0.3.0 before or with this release. A removal now closes the
out-of-band finding, and older rules take any close as an explanation, so rights nobody
granted that were removed within the rule's hour would stop alerting.

### Breaking changes

None.

### Security

None.

### Changes

- The server records where each Mac says its key is kept, which agent 0.2.0 sends when it
  enrolls: `key_storage` on each enrollment in `GET /v1/enrollments` is `secure_enclave`,
  `software`, or empty for older agents and enrollments from before this release. It's the
  Mac's own claim; the server can't check it (`docs/data-handling.md`). **Enrollments**
  shows it under each key's fingerprint as Secure Enclave, File or Not reported, suggests
  revoking an active file key so the Mac enrolls again with a new one, and says so when a
  Mac waiting for approval would swap a Secure Enclave key for one that isn't.
- After an upgrade, the console's update check no longer says "Up to date" from a release
  list fetched before the release. When the list doesn't include the running server's
  version, the admin's browser asks GitHub again, at most once an hour, and keeps the list
  it has if that fails. A server newer than every release, such as a build that isn't
  released, says "newer than the latest release" (`docs/data-handling.md`).
- Settings → Updates has a **Check now** button for admins, beside "Last checked" and on
  "Couldn’t check for updates", which asks GitHub for the release list straight away
  instead of waiting out the day. It asks at most once a minute (`docs/data-handling.md`).
- Settings → Updates has a **Show pre-releases** switch, off by default, kept in the
  admin's browser. When it's on, the console's notices offer release candidates too, saying
  so, with the `upgrade.sh` command for the candidate, and Settings names the newest
  candidate next to the latest release. A server running a candidate hears about newer
  candidates whatever the switch says, as before.
- The server accepts `admin.out_of_band_removed` from agent 0.2.0, ends the session as
  "Removed without a grant" and exports a Revoke Privileges record.
- A console revoke, an automatic removal, or rights the heartbeat sees gone now close the
  out-of-band finding with status "Rights removed". Before, a console revoke left it open.
- The Sentinel workbook (`integrations/sentinel/workbook.arm.json`) and the Splunk
  dashboard (`integrations/splunk/altiward_overview.xml`) count `admin.out_of_band_removed`
  as a session end, so re-import them: older copies show sessions agent 0.2.0 removed as
  still open.

## Agent 0.1.1 - 2026-10-23

### Upgrade order

Upgrade the server to 0.2.0 first. An older server ends the replaced session as `revoked`
and doesn't close its finding.

Deploy this release's `corp.sap.privileges.plist` keys to your Privileges profile with the
package: its `PostChangeExecutableChecksum` is this build's hook. With the old checksum,
Privileges stops running the hook and Altiward raises "SAP Privileges no longer reports to
Altiward".

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
- With SAP Privileges 2.6 or later and its system extension on (macOS 14+), the agent
  reads what the extension logs. Admin rights nobody granted carry the process that
  added the user (`detail.instigator`: executable, signing ID, team ID, PID, TTY), and
  each attempt the extension blocked on Privileges (deleting, renaming or unloading it)
  is sent as `agent.tamper` with check `privileges_blocked`. Privileges keeps these on
  the Mac; nothing changes without the extension. `sudo altiward-agent privileges-audit`
  prints what the agent reads. `docs/data-handling.md` lists what is collected.
- `agent.health` reports Privileges 2.7's daily `AdminBudget` as
  `privileges.admin_budget_minutes`. Privileges enforces it; the agent only reports it.

## Server 0.2.0 - 2026-10-23

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
- The Sentinel export's managed identity also works on Azure Container Apps, through the
  identity endpoint the platform gives the app, and `setup.sh --identity <client ID>`
  sets Sentinel up for a user-assigned identity, with no app registration or secret
  (`integrations/sentinel/README.md`).
- Deploy to Azure (Preview): a template creates the server in your Azure subscription on
  Azure Container Apps, with Postgres on a private network, the database URL and tokens
  in Key Vault, and a caddy container that keeps the console to the networks you list
  while Macs report from anywhere (`deploy/azure/README.md`). The server sends nothing
  new; on Azure, Azure keeps its logs for 30 days (`docs/data-handling.md`).
- On Azure Container Apps, the console's notice of a newer server names the image to
  change the container app to, instead of the `upgrade.sh` command.
- The install guide, `docs/install.md`, has a diagram of how the parts connect, a picture
  of what to expect after each step, the paths in Jamf Pro and Intune, and troubleshooting
  for a Mac that never appears, grants that show as "Without a grant" and certificate
  errors. The bundle includes its pictures.
- Admin rights without a grant show the process that added the user, "Added by
  /usr/sbin/dseditgroup", on the session's timeline, and the SIEM export puts it in the
  finding's description and evidence. Attempts SAP Privileges blocked on itself are
  exported as High findings, "SAP Privileges blocked an attempt to tamper with it", and
  shown as Blocked in the Mac's tamper alerts. Both need agent 0.1.1 and Privileges 2.6
  or later with its system extension on.
- A Mac's details in Fleet show Privileges' daily admin budget (`AdminBudget`, Privileges
  2.7+) when it is set. Needs agent 0.1.1.

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
