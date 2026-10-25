# Backend

`altiward-api` is one Go binary. It handles agent ingestion, serves the read API behind
the console, and runs the SIEM export workers and the monitor that raises `agent.silent`
when a Mac stops checking in.

| Package | Role |
| --- | --- |
| `internal/event` | Core event type, strict decoding, validation |
| `internal/session` | Pure reducers: events → elevation sessions and device records |
| `internal/store` | `Store` interface; Postgres (production) and in-memory (tests, dev) implementations |
| `internal/api` | HTTP handlers |
| `internal/ocsf` | Mapping to OCSF 1.9.0 for export |
| `internal/export` | Outbox worker plus Splunk, Sentinel and syslog (CEF) sinks |
| `internal/monitor` | Events the backend raises itself: `agent.silent` for a Mac that stops checking in |
| `internal/retention` | Removes audit entries past `ALTIWARD_AUDIT_RETENTION_DAYS`, daily |
| `internal/diagnose` | The `altiward-api diagnose` support report |
| `internal/release` | `OldestSupportedAgent` and the agent version check |
| `internal/sso` | Console single sign-on: OIDC with PKCE through go-oidc, groups to roles. `sso/ssotest` is a fake identity provider for tests |
| `internal/auth`, `internal/config` | Bearer tokens and console roles; `ALTIWARD_*` environment |

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
| `POST /v1/agent/enroll` | Enrollment token. `{"serial", "hardware_uuid", "public_key"}` (base64 P-256 SubjectPublicKeyInfo). Responds `{"device_id", "status"}`: 201 for a new credential, 200 for the same key again. |
| `POST /v1/agent/events` | Device signature. `{"events": [...]}`, up to 500. Responds `{"accepted": [], "duplicate": [], "rejected": [{"event_id", "error"}]}`. Events whose serial is not the signing Mac's are rejected. Auth failures carry `code`: `credential_invalid`, `enrollment_pending` or `clock_skew`. |
| `GET /v1/sessions` | Newest first. Query: `user`, `device`, `open=true`, `since`, `until` (RFC 3339, on start time), `limit` (≤ 500). Each session adds `open`, `allowed_seconds`, `actual_seconds` and `overran`. |
| `GET /v1/sessions/{id}` | `{"session": ..., "events": [...]}`: the timeline, oldest first, with `received_at`. |
| `GET /v1/devices` | Fleet inventory: versions, last check-in, current `admin_members` and `permanent_admins`, Privileges config. |
| `GET /v1/overview?days=7\|30\|90` | The console's overview, worked out by `internal/report` from session and device state and each SIEM's queue: admins now by source, alerts, the period's elevations per day (per week over 90 days), median time held against allowed, the top five people and Macs, agent versions and SIEM state. 30 days by default. |
| `GET /v1/enrollments` | Device credentials, newest first. Query: `status` (`active`, `pending`, `revoked`), `serial`. |
| `POST /v1/enrollments/{device_id}/approve` | Activate a pending re-enrollment; revokes the Mac's previous credential. |
| `POST /v1/enrollments/{device_id}/revoke` | Revoke a credential. |
| `GET /v1/settings`, `PUT /v1/settings` | Tenant settings: `{"reenrollment_requires_approval": true, "silent_after_hours": 0, "silent_alerts_off": false}`. Approval defaults to on; an omitted or null flag also means on. Only explicit `false` permits automatic identity replacement. `silent_after_hours` is 1 to 720, or 0 for the default of 72. `silent_alerts_off` stops new `agent.silent` alerts; a Mac already reported still resumes. `PUT` replaces them all. |
| `GET /v1/exports` | Each configured SIEM: `{"sink", "pending", "failing", "oldest_queued_at", "max_attempts", "last_error", "last_delivered_at"}`. `last_delivered_at` is when it last accepted something for this tenant, or null. |
| `POST /v1/exports/test`, `POST /v1/exports/{sink}/retry` | Admin. Queue a test event for every SIEM, or make a failing SIEM's waiting items due now. Both are audited. |
| `POST /v1/sessions/{id}/revoke` | Queue a `revoke_admin` command for an open session's Mac and user. 409 if the session has ended. |
| `POST /v1/devices/{serial}/revoke` | Queue a revoke of every admin on the Mac except permanent admins; body `{"user": "..."}` targets one account. |
| `GET /v1/commands`, `GET /v1/commands/{id}` | Commands with `status` (`pending`, `completed`, `failed`, `skipped`, `expired`) and the agent's `result`. Query: `serial`, `status`. `issued_by` is the actor, as in the audit log. |
| `GET /v1/console-sessions` | Admin. Who is signed in to the console through single sign-on: `{"sessions": [{"id", "actor", "name", "role", "created_at", "ends_at", "expires_at", "current"}]}`. `id` is the hex of the session's stored hash, never its cookie. |
| `DELETE /v1/console-sessions/{id}` | Admin. Ends that sign-in, audited as `end_console_session`. 204, or 404 if it has already ended. |
| `GET /v1/about` | `{"version", "oldest_supported_agent", "tamper_severities", "update_check"}`: the server's version, the oldest agent minor release it accepts, the severity each known tamper check's failure is exported with, and whether the console may check GitHub for newer releases (`ALTIWARD_UPDATE_CHECK`). On Azure Container Apps it adds `"platform": "azure-container-apps"` and `"app"`, the app's name. The console shows the version, tags older agents, gives failing checks their severity and tells admins when a newer release is out, and how to install it where the server runs. |
| `GET /v1/audit` | Console actions, newest first: `{"entries": [{"id", "at", "actor", "action", "target", "detail", "seq"}]}`. Actions: `revoke_session`, `revoke_device`, `approve_enrollment`, `revoke_enrollment`, `change_settings` (with `previous` and `settings`), `sign_in` (with `role`, `name` and `subject`), `sign_out`, `test_export`, `retry_exports` and `end_console_session` (its target is the signed-in person's actor). `actor` is the person's email with single sign-on; for a token it is `token:` and the first 8 hex digits of its SHA-256, or `break-glass:` and the same digits once single sign-on is on. Entries in the same instant list newest first by `seq`, the order recorded. Query: `before` (RFC 3339), `before_seq` (with `before`: the next page starts after the last entry's `at` and `seq`, so none are skipped), `limit` (≤ 500). Each entry is written in the transaction that made the change; the table is append-only, except that entries older than 365 days can be removed by retention. |
| `GET /v1/auth/config` | No authentication. `{"sso": true}` when single sign-on is set up. |
| `GET /v1/auth/login` | No authentication. Starts single sign-on: sets a short-lived sign-in cookie and redirects to the identity provider. Query: `next`, a path on this site to return to. |
| `GET /v1/auth/callback` | Where the identity provider sends the browser back. Sets the session cookie (`__Host-altiward_session`, HttpOnly, Secure, SameSite=Lax) and redirects to `next`, or to `/?sso_error=` with `no_role`, `groups`, `expired`, `denied`, `unavailable` or `failed`. |
| `GET /v1/auth/me` | `{"actor", "name", "role", "method"}`, plus `csrf_token` and `ends_at` for a single sign-on session. `method` is `sso` or `token`. |
| `POST /v1/auth/logout` | Ends the session (CSRF token required) and records `sign_out`. 204. A no-op for a token. |
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
| `ALTIWARD_UPDATE_CHECK` | `true` | `false` stops the console's browser asking `api.github.com` for newer releases, and drops it from the console's `connect-src`. The server never asks. |
| `ALTIWARD_CONSOLE_DIR` | None | The built console (`console/dist`) to serve from the API's origin. Unset means API only. Start fails if it has no `index.html`. |
| `ALTIWARD_OIDC_ISSUER` | None | The identity provider's issuer URL. Turns on console single sign-on; console tokens become break-glass logins. |
| `ALTIWARD_OIDC_CLIENT_ID`, `_CLIENT_SECRET` | None | The app registration. The secret may be empty for a public client. |
| `ALTIWARD_CONSOLE_URL` | None | Required with single sign-on: the console's URL. The redirect URL to register is this plus `/v1/auth/callback`. https, or http on localhost. |
| `ALTIWARD_OIDC_ADMIN_GROUPS`, `_OPERATOR_GROUPS`, `_VIEWER_GROUPS` | None | Comma-separated group IDs or names, as the groups claim carries them. At least one. |
| `ALTIWARD_OIDC_GROUPS_CLAIM` | `groups` | The claim holding groups; `roles` for Entra app roles |
| `ALTIWARD_OIDC_SCOPES` | `openid email profile` | Okta needs `groups` added |
| `ALTIWARD_OIDC_TENANT` | the only tenant | The Altiward tenant people who sign in belong to. Required when the tokens name more than one. |
| `ALTIWARD_SPLUNK_HEC_URL`, `_HEC_TOKEN`, `_INDEX` | None | Enables the Splunk sink |
| `ALTIWARD_SENTINEL_ENDPOINT`, `_DCR_ID`, `_STREAM`, `_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET` | stream `Custom-AltiwardOCSF` | Enables the Sentinel sink |
| `ALTIWARD_SYSLOG_ADDR`, `_TLS`, `_CA_FILE`, `_FORMAT`, `_FRAMING` | TLS, `cef`, `octet` | Enables the syslog sink; see [integrations/syslog](../integrations/syslog/README.md) |

Each sink gets every exportable agent event and every console action from the audit log
(OCSF API Activity, event type `console.<action>`). Both share one outbox queue per sink,
written in the transaction that stores the event or makes the change.

Export sinks are global per deployment for now. The outbox already records the tenant, so
per-tenant sink configuration can come later without a data migration.

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
it refuses a configured one) and `version`.

```sh
make backend-test    # unit tests; the Postgres store suite is skipped
make test-db         # also runs the store suite against Postgres
```

```sh
curl -H 'Authorization: Bearer dev-console-token-001' localhost:8080/v1/sessions # gitleaks:allow
```
