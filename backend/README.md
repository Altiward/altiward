# Backend

`altiward-api` is one Go binary. It handles agent ingestion, serves the read API behind
the console, and runs the SIEM export workers and the monitor that raises `agent.silent`
when a Mac stops checking in. The backend raises two other events itself: `agent.enrollment`,
when a Mac enrols a key, and `agent.admin_group`, the admin group of a Mac, so that a SIEM
keeps it after the health readings expire. Agents can't send any of the three: the API
refuses them.

| Package | Role |
| --- | --- |
| `internal/event` | Core event type, strict decoding, validation |
| `internal/session` | Pure reducers: events → elevation sessions and device records |
| `internal/store` | `Store` interface; Postgres (production) and in-memory (tests, dev) implementations |
| `internal/api` | HTTP handlers. `enrollment_event.go` builds the `agent.enrollment` event stored when a key enrols |
| `internal/ocsf` | Mapping to OCSF 1.9.0 for export |
| `internal/export` | Outbox worker plus Splunk, Sentinel and syslog (CEF) sinks |
| `internal/admingroup` | Decides the `agent.admin_group` events (`changed` and `snapshot`) from a health reading and the group last sent for the Mac |
| `internal/monitor` | Raises `agent.silent` for a Mac that stops checking in, and the daily `agent.admin_group` snapshots. A retired Mac gets no new silence alert and no snapshot |
| `internal/retention` | Removes audit entries past `ALTIWARD_AUDIT_RETENTION_DAYS`, daily. `History` removes events, ended sessions, commands and quiet Macs past each organisation's `history_days`, daily, and never what a SIEM still waits for ([data handling](../docs/data-handling.md#how-long-history-is-kept)) |
| `internal/diagnose` | The `altiward-api diagnose` support report |
| `internal/release` | `OldestSupportedAgent` and the agent version check |
| `internal/sso` | Console single sign-on: OIDC with PKCE through go-oidc, groups to roles. `sso/ssotest` is a fake identity provider for tests |
| `internal/auth`, `internal/config` | Bearer tokens and console roles; `ALTIWARD_*` environment |

## Fuzzing

`scripts/test-fuzz.sh` runs native Go fuzz campaigns for event decoding and validation,
signed-request headers, P-256 public keys, request signatures, rotation proofs, command
results and the actual enrolment HTTP handler. Seeds include the shared signing and
rotation vectors, command result, current event examples and frozen supported-agent events.
Ordinary `go test` also runs these seeds.

Each campaign runs for five seconds with two workers in CI, one target at a time. For a
longer local run, use `FUZZ_TIME=60s FUZZ_PARALLEL=2 scripts/test-fuzz.sh`. Individual inputs
are capped at 128 KiB (16 KiB for headers and public keys). The enrolment target uses a
fresh in-memory store per input and requires no listening socket or external service.
It checks persisted credentials and retry/export idempotence while preserving support
for unknown fields from later agents. Event and command-result decoding remain strict.

Keep a reproducible failing input as a regression seed after checking it against the
wire contract. Short campaigns supplement normal, race and state/concurrency tests;
they do not replace those checks.

## HTTP handler layout

`internal/api/api.go` constructs the server and registers routes. Handlers are grouped by
responsibility: `auth.go` for console sign-in, `ingest.go` for incoming agent events,
`sessions.go` for elevation sessions, `devices.go` for fleet and enrollment, and
`settings.go` for tenant policy. Commands, audit, exports and overview have their own
files. Console-session administration is in `console_sessions.go` and static console
serving in `console.go`. All belong to the same package; moving between files does not
change an endpoint or its authorisation.

## API

Agents enroll once with a tenant enrollment token (`Authorization: Bearer <token>`), then
sign every request with their device key: `Authorization: AltiwardDevice <device_id>`,
`X-Altiward-Timestamp` (Unix seconds, within 5 minutes of the server's clock) and
`X-Altiward-Signature`, an ECDSA P-256 signature over `ALTIWARD-SIG-V1`, the method, the
path and query, the timestamp and the body's SHA-256, one per line
([signature-vector.json](../docs/schema/signature-vector.json) is a worked example).
A rotation (`POST /v1/agent/rotate`) also carries a proof that the new key is held: an
ECDSA P-256 signature by the new key over `ALTIWARD-ROTATE-V1`, the current `device_id` and
the lowercase hex SHA-256 of the new key's SubjectPublicKeyInfo DER, one per line, with no
trailing newline
([rotation-vector.json](../docs/schema/rotation-vector.json) is a worked example).
Console endpoints take a console token, or the session cookie single sign-on sets.
Every query is scoped to the caller's tenant.

Each console endpoint needs a role. **Viewer** reads everything. **Operator** also
revokes (`POST /v1/sessions/{id}/revoke`, `POST /v1/devices/{serial}/revoke`). **Admin**
also approves and revokes enrollments and changes settings. A console token is an admin.
A person signed in through single sign-on has the highest role their groups map to. A
request that changes anything with the session cookie must send the session's CSRF
token in `X-CSRF-Token`; requests with a token don't.

| Method and path | Purpose |
| --- | --- |
| `POST /v1/agent/enroll` | Enrollment token. `{"serial", "hardware_uuid", "public_key", "key_storage"}` (`public_key` is a base64 P-256 SubjectPublicKeyInfo; `key_storage` is optional: `secure_enclave` or `software`). Responds `{"device_id", "status"}`: 201 for a new credential, 200 for the same key again. A new key is `pending` when the Mac enrolled before and approval is on, or when its `hardware_uuid` differs from the Mac's active key's, whatever the setting. Over a limit (`ALTIWARD_ENROLL_NEW_MACS_PER_HOUR` or `ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY`) it answers 429 with `Retry-After: 3600` and `code`: `enrollment_rate_limited`; the same key again is never limited. |
| `POST /v1/agent/events` | Device signature. `{"events": [...]}`, up to 500. Responds `{"accepted": [], "duplicate": [], "rejected": [{"event_id", "error", "code"}]}`. Events whose serial is not the signing Mac's are rejected with `code`: `device_mismatch` (no other rejection has a `code`). Auth failures carry `code`: `credential_invalid`, `enrollment_pending` or `clock_skew`. |
| `POST /v1/agent/rotate` | Device signature, by the key being replaced. `{"public_key", "key_storage", "proof"}`: the new key as in enrolment, and its proof (above). Responds `{"device_id", "status"}`: 201 and `active` for the new key, which takes the old key's tenant, serial and hardware UUID, with no approval; the old key is revoked in the same step. The same body again answers 200 with the same `device_id` and the new key's current `status` (`revoked` if an admin has revoked it since), at any time, and is never rate limited. Refused with 400 and `code` `rotation_invalid` (the body doesn't decode, `public_key` isn't P-256 or is the signing key, or the proof is wrong); 409 `key_in_use` (any credential holds the key, in any tenant); 409 `rotation_not_allowed` (the signing key claims the Secure Enclave); 429 `rotation_rate_limited` with `Retry-After` (the signing key has been active less than 24 hours); 403 `enrollment_pending`; 401 `credential_invalid` (the signing key is revoked, or was rotated to a different key). |
| `GET /v1/sessions` | Newest first. Query: `user`, `device`, `open=true`, `since`, `until` (RFC 3339, on start time), `limit` (≤ 500). Each session adds `open`, `allowed_seconds`, `actual_seconds` and `overran`. |
| `GET /v1/sessions/{id}` | `{"session": ..., "events": [...]}`: the timeline, oldest first, with `received_at`. |
| `GET /v1/devices` | Fleet inventory: versions, last check-in, current `admin_members` and `permanent_admins`, Privileges config. `retired_at` is when an admin revoked the Mac's only key, left out while the Mac is in use. Retired Macs are still returned, for the console to hide by default. |
| `GET /v1/overview?days=7\|30\|90` | The console's overview, worked out by `internal/report` from session and device state and each SIEM's queue: admins now by source, alerts, the period's elevations per day (per week over 90 days), median time held against allowed, the top five people and Macs, agent versions and SIEM state. 30 days by default. Retired Macs are left out of the counts of Macs (failing checks, silent, health, agent versions) but not of open sessions or what happened in the period. |
| `GET /v1/enrollments` | Device credentials, newest first. Query: `status` (`active`, `pending`, `revoked`), `serial`. A key made by rotation has `rotated_from`, the key it replaced; a key that rotation replaced is `revoked` and has `rotated_to`, the key that replaced it. Both are left out when empty. |
| `POST /v1/enrollments/{device_id}/approve` | Activate a pending re-enrollment; revokes the Mac's previous credential. |
| `POST /v1/enrollments/{device_id}/revoke` | Revoke a credential. Revoking a Mac's only active key, with none pending, retires the Mac (`retired_at`), and the entry in Activity says `retired`, and `open_sessions` and `failing_checks` when either applies. Rejecting a pending key, or a revoke that changes nothing, never retires a Mac; any new key for the Mac clears `retired_at`. A key that rotation replaced, whose lineage still has an active key, is refused with 409 `credential_rotated` and `current_device_id`, the key in use, and nothing changes: revoke that key instead. |
| `GET /v1/settings`, `PUT /v1/settings` | Tenant settings: `{"reenrollment_requires_approval": true, "new_mac_requires_approval": false, "silent_after_hours": 0, "silent_alerts_off": false}`. Approval defaults to on; an omitted or null flag also means on. Only explicit `false` permits automatic identity replacement. `new_mac_requires_approval` holds every serial's first key for approval too; it is off by default and when omitted. `silent_after_hours` is 1 to 720, or 0 for the default of 72. `silent_alerts_off` stops new `agent.silent` alerts; a Mac already reported still resumes. `history_days` is how long history is kept: 0 for the default (a year with a SIEM connected, for good without one), -1 to keep it for good, or 90 to 3650 days. A `PUT` that leaves `history_days` out keeps the stored value. `PUT` replaces the rest. |
| `GET /v1/retention` | Viewer. The history period in force: `{"history": {"days", "kept_for_good", "reason", "held_before", "waiting_for_backfill"}}`. `reason` is `default_siem`, `default_no_siem`, `set` or `kept_for_good`. `held_before` is the SIEM coverage date while the default period keeps back history received before it, otherwise null. `waiting_for_backfill` is true until the admin group has been sent from stored readings: expiry doesn't start before that. |
| `GET /v1/exports` | Each configured SIEM: `{"sink", "pending", "failing", "oldest_queued_at", "max_attempts", "last_error", "last_delivered_at"}`. `last_delivered_at` is when it last accepted something for this tenant, or null. |
| `POST /v1/exports/test`, `POST /v1/exports/{sink}/retry` | Admin. Queue a test event for every SIEM, or make a failing SIEM's waiting items due now. Both are audited. |
| `GET /v1/mdm` | The Intune connection: `{"configured": true, "source": "intune", "last_success_at", "last_error_at", "last_error", "devices", "silence_held_at", "silence_held"}`, or `{"configured": false}` when Intune is off. `devices` is how many Macs the last successful sync copied; a failed sync keeps that copy and records `last_error`. `silence_held_at` and `silence_held` say when silence alerts were last held back because too many Macs tripped at once, and how many. Each time is left out until it first happens. |
| `GET /v1/mdm/devices` | The Macs Intune manages, from the server's copy, refreshed every 15 minutes: `{"devices": [{"serial", "primary_upn", "name", "last_check_in"}]}`, by serial. `primary_upn` is Intune's primary user; `last_check_in` is the Mac's last check-in with Intune, left out if it has never checked in. Intune's and Entra ID's device IDs are never shown. Empty when Intune is off. |
| `POST /v1/sessions/{id}/revoke` | Queue a `revoke_admin` command for an open session's Mac and user. 409 if the session has ended. |
| `POST /v1/devices/{serial}/revoke` | Queue a revoke of every admin on the Mac except permanent admins; body `{"user": "..."}` targets one account. |
| `GET /v1/commands`, `GET /v1/commands/{id}` | Commands with `status` (`pending`, `completed`, `failed`, `skipped`, `expired`) and the agent's `result`. Query: `serial`, `status`. `issued_by` is the actor, as in the audit log. |
| `GET /v1/console-sessions` | Admin. Who is signed in to the console through single sign-on: `{"sessions": [{"id", "actor", "name", "role", "created_at", "ends_at", "expires_at", "current"}]}`. `id` is the hex of the session's stored hash, never its cookie. |
| `DELETE /v1/console-sessions/{id}` | Admin. Ends that sign-in, audited as `end_console_session`. 204, or 404 if it has already ended. |
| `GET /v1/about` | `{"version", "oldest_supported_agent", "tamper_severities", "update_check"}`: the server's version, the oldest agent minor release it accepts, the severity each known tamper check's failure is exported with, and whether the console may check GitHub for newer releases (`ALTIWARD_UPDATE_CHECK`). On Azure Container Apps it adds `"platform": "azure-container-apps"` and `"app"`, the app's name. The console shows the version, tags older agents, gives failing checks their severity and tells admins when a newer release is out, and how to install it where the server runs. |
| `GET /v1/audit` | Console actions, newest first: `{"entries": [{"id", "at", "actor", "action", "target", "detail", "seq"}]}`. Actions: `revoke_session`, `revoke_device`, `approve_enrollment`, `revoke_enrollment`, `change_settings` (with `previous` and `settings`), `sign_in` (with `role`, `name` and `subject`), `sign_out`, `test_export`, `retry_exports` and `end_console_session` (its target is the signed-in person's actor). The server writes three more by itself, with the actor `altiward:server`: `expire_history` (one for each organisation per run that removed anything: the cutoff, the period and why, and counts), `remove_device` (a Mac that stopped checking in, removed with its history: its serial, last check-in, counts and the event ID of its open `agent.silent` alert, if any) and `revoke_enrollment` for each key the server revoked with the Mac. `actor` is the person's email with single sign-on; for a token it is `token:` and the first 8 hex digits of its SHA-256, or `break-glass:` and the same digits once single sign-on is on. Single sign-on refuses to sign in a person whose actor (their email, else username, UPN or subject) starts with `altiward:`, `token:` or `break-glass:`. Entries in the same instant list newest first by `seq`, the order recorded. Query: `before` (RFC 3339), `before_seq` (with `before`: the next page starts after the last entry's `at` and `seq`, so none are skipped), `limit` (≤ 500). Each entry is written in the transaction that made the change; the table is append-only, except that entries older than 365 days can be removed by retention. |
| `GET /v1/auth/config` | No authentication. `{"sso": true}` when single sign-on is set up. |
| `GET /v1/auth/login` | No authentication. Starts single sign-on: sets a short-lived sign-in cookie and redirects to the identity provider. Query: `next`, a path on this site to return to, and `select_account=1`, which asks the identity provider for its account picker (as does the first sign-in after a sign-out). |
| `GET /v1/auth/callback` | Where the identity provider sends the browser back. Sets the session cookie (`__Host-altiward_session`, HttpOnly, Secure, SameSite=Lax) and redirects to `next`, or to `/?sso_error=` with `no_role`, `groups`, `expired`, `denied`, `unavailable` or `failed`. |
| `GET /v1/auth/me` | `{"actor", "name", "role", "method"}`, plus `csrf_token` and `ends_at` for a single sign-on session. `method` is `sso` or `token`. |
| `POST /v1/auth/logout` | Ends the session (CSRF token required) and records `sign_out`. 204, or with `ALTIWARD_OIDC_PROVIDER_SIGN_OUT=true` and an identity provider that offers an `end_session_endpoint`, 200 with `Cache-Control: no-store` and `{"provider_sign_out_url"}`, where the console sends the browser next. The session has ended and `sign_out` is recorded either way. With single sign-on it also sets a browser-session cookie (`__Host-altiward_signed_out`, HttpOnly, Secure, SameSite=Lax) so the next sign-in shows the account picker. A no-op for a token. |
| `GET /v1/agent/commands` | Device signature. This Mac's commands awaiting a result. With `?wait=N` (0 to 50) the server holds the request until one is queued. |
| `POST /v1/agent/commands/{id}/result` | Device signature. Report a result; the first one wins. |
| `GET /healthz` | Liveness. |

Session `end_reason`: `revoked`, `inferred`, `expired_enforced`, `remote_revoke`,
`permanent_admin` (found without a grant, then made a permanent admin; the rights stay) or
`privileges_grant` (found without a grant, then replaced by a Privileges grant; the rights stay) or
`out_of_band_removed` (found without a grant, then removed by the agent).
A session's `source` is `privileges` or `out_of_band`.

Session `flags`: `unverified_claim`, `orphan_revoke`, `out_of_band`, `inferred_end`,
`overdue`, `persistence_detected`, `after_out_of_band` (a Privileges grant that replaced an
out-of-band session).

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `ALTIWARD_LISTEN_ADDR` | `:8080` | |
| `ALTIWARD_DATABASE_URL` | None | Postgres URL. Unset means the in-memory store (development only). Migrations run on start. |
| `ALTIWARD_AGENT_TOKENS` | None | Enrollment tokens, `tenant=token,tenant=token` (tokens ≥ 16 chars). They only enroll. |
| `ALTIWARD_CONSOLE_TOKENS` | None | Same format |
| `ALTIWARD_EXPORT_INTERVAL` | `10s` | How often export workers poll |
| `ALTIWARD_AUDIT_RETENTION_DAYS` | None | Remove audit entries older than this, daily; at least 365. Unset or `0` keeps them forever. Entries still waiting for export stay until sent, and the database refuses to delete any younger than 365 days. |
| `ALTIWARD_ENROLL_NEW_MACS_PER_HOUR` | `1000` | How many serials new to a tenant may enrol in an hour. More are refused with 429 until the hour has passed. `0` turns the limit off. |
| `ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY` | `5` | How many keys one serial may enrol in 24 hours, in any status. `0` turns the limit off. |
| `ALTIWARD_UPDATE_CHECK` | `true` | `false` stops the console's browser asking `api.github.com` for newer releases, and drops it from the console's `connect-src`. The server never asks. |
| `ALTIWARD_CONSOLE_DIR` | None | The built console (`console/dist`) to serve from the API's origin. Unset means API only. Start fails if it has no `index.html`. |
| `ALTIWARD_OIDC_ISSUER` | None | The identity provider's issuer URL. Turns on console single sign-on; console tokens become break-glass logins. |
| `ALTIWARD_OIDC_CLIENT_ID`, `_CLIENT_SECRET` | None | The app registration. The secret may be empty for a public client. |
| `ALTIWARD_CONSOLE_URL` | None | Required with single sign-on: the console's URL. The redirect URL to register is this plus `/v1/auth/callback`. https, or http on localhost. |
| `ALTIWARD_OIDC_ADMIN_GROUPS`, `_OPERATOR_GROUPS`, `_VIEWER_GROUPS` | None | Comma-separated group IDs or names, as the groups claim carries them. At least one. |
| `ALTIWARD_OIDC_GROUPS_CLAIM` | `groups` | The claim holding groups; `roles` for Entra app roles |
| `ALTIWARD_OIDC_SCOPES` | `openid email profile` | Okta needs `groups` added |
| `ALTIWARD_OIDC_PROVIDER_SIGN_OUT` | `false` | `true` makes signing out of the console also sign the person out of Entra ID, through the provider's `end_session_endpoint`. Register `<ALTIWARD_CONSOLE_URL>/signed-out` as a redirect URI in the app registration. Refused unless the issuer is `login.microsoftonline.com`, until 1.2.0. |
| `ALTIWARD_OIDC_TENANT` | the only tenant | The Altiward tenant people who sign in belong to. Required when the tokens name more than one. |
| `ALTIWARD_SPLUNK_HEC_URL`, `_HEC_TOKEN`, `_INDEX` | None | Enables the Splunk sink |
| `ALTIWARD_SENTINEL_ENDPOINT`, `_DCR_ID`, `_STREAM`, `_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET` | stream `Custom-AltiwardOCSF` | Enables the Sentinel sink |
| `ALTIWARD_INTUNE_AUTH` | None | Turns on the read-only Microsoft Graph connection to Intune: `secret`, `certificate` or `managed-identity`. Setting any other `ALTIWARD_INTUNE_*` without it stops the server. Needs a server whose tokens name one tenant. Not an export sink. |
| `ALTIWARD_INTUNE_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_CERTIFICATE_FILE` | None | The app registration for `secret` (tenant, client ID and secret) or `certificate` (tenant, client ID and a PEM file with the certificate and private key). `managed-identity` needs none; `_CLIENT_ID` picks a user-assigned identity. |
| `ALTIWARD_SYSLOG_ADDR`, `_TLS`, `_CA_FILE`, `_FORMAT`, `_FRAMING` | TLS, `cef`, `octet` | Enables the syslog sink; see [integrations/syslog](../integrations/syslog/README.md) |

Each sink gets every exportable agent event and every console action from the audit log
(OCSF API Activity, event type `console.<action>`), including what the server does by itself,
whose actor maps to a System user, "Altiward server". Both share one outbox queue per sink,
written in the transaction that stores the event or makes the change. An `agent.admin_group`
event becomes OCSF Group Management (3006) records: one for each person added, removed or in
the group, and one for the Mac. Health readings and command results are never exported.

Export sinks are global per deployment for now. The outbox already records the tenant, so
per-tenant sink configuration can come later without a data migration. Every replica must have
the same sinks: a replica without one stores events without queuing them for it. The server
notes when it first started with each sink, and under the default history period removes
nothing received before the latest of those dates.

## Run and test

```sh
make run-api         # Postgres via docker compose, dev tokens, :8080
make run-api-console # the same, serving the built console as in production
make image           # production image: the API serving the console (Dockerfile); VERSION=0.1.0 stamps it
```

Releases come from a `server-vX.Y.Z` tag (`.github/workflows/release-server.yml`): a signed
multi-arch image on `ghcr.io`, the same image saved per platform, the deployment bundle
(`scripts/server-bundle.sh`), the notes from `CHANGELOG.md` (`scripts/release-notes.sh`)
and signed `SHA256SUMS`. See [docs/releasing.md](../docs/releasing.md).
Admins deploy it with [deploy/compose](../deploy/compose/); see the
[install guide](../docs/install.md). The binary has subcommands besides running the
server: `health` (exit 0 if the local server answers `/healthz`, for container health
checks), `diagnose` (a support report as JSON, secrets hidden, database read without
migrating), `drop-exports SINK` (drop the export queue of a sink no longer configured;
it refuses a configured one), `replay-exports SINK SINCE` (queue what was received since a
date for a configured sink, and move that sink's coverage date back to it) and `version`.

```sh
make backend-test    # unit tests; the Postgres store suite is skipped
make test-db         # also runs the store suite against Postgres
```

```sh
curl -H 'Authorization: Bearer dev-console-token-001' localhost:8080/v1/sessions # gitleaks:allow
```
