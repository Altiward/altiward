# Architecture and source layout

Altiward has three running components: a Mac agent, a server and a browser console.
The root [repository layout](../README.md#repository-layout) shows where their source,
deployment configuration and supporting tools live.

## Mac agent

`agent/` is a Swift package. `AltiwardHook` is SAP Privileges' post-change executable;
it forwards a claim over XPC. `AltiwardDaemon` runs as root, checks the real admin group,
maintains the elevation ledger, performs integrity and persistence checks, enforces
configured expiry, removes admin rights nobody granted if configured to, handles revoke
commands and delivers queued events. Both use `AltiwardCore`.

The hook is untrusted. The daemon verifies its claims and supplies timestamps. See the
agent's [design notes](../agent/README.md#design-notes) for the trust model.

MDM templates live in `deploy/mdm/`. Package construction, installation scripts and
LaunchDaemon resources live in `agent/packaging/`. The package builder generates a
Privileges profile pinned to the hook it signs.

## Server and console

`backend/cmd/altiward-api` assembles the Go server. `backend/internal/` contains the
HTTP API, authentication, event validation, session/device reducers, storage, reports,
export workers, monitoring, history expiry and the Intune connection. Tests are colocated
with the packages they exercise. Postgres migrations stay with their embedded store
implementation.

The ingestion transaction stores an event, updates derived state and queues its SIEM
exports. Export workers retry until a destination accepts the records. Reducers in
`internal/session` build device and session state; storage implementations share them.

`console/` is the React application. Views call the typed API client; shared controls
live in `src/components/`. Hooks manage API loading, command results and release checks.
Production builds put the console and server in the same Docker image and origin.

The server authorises every console endpoint. Console mutations are audited in the
transaction that makes the change. Revoke requests become commands that the Mac's
signed long-poll request receives; the agent performs and reports the action.

## Intune connection

The optional MDM connection is read-only and outbound: the server signs in to Microsoft
Graph and never writes to Intune. `backend/internal/mdm` keeps a copy of the Macs Intune
manages, refreshed every 15 minutes, through the Graph client in `internal/intune`. The
enrolment handler asks it about the `MDMDeviceID` an enrolling Mac sends, and the silence
monitor uses the copy to raise `agent.silent` early for a Mac Intune still hears from. A
match never approves a key by itself. The Graph permission setup lives in `deploy/intune/`
and `deploy/azure/intune-read.bicep`, with the script that uploads the Mac profiles to
Intune, which runs as the admin and is separate from the server.

## SIEM boundaries

`integrations/` is a separate Go module containing reusable transport clients. The
server owns the mapping from native events and console audit entries to OCSF in
`backend/internal/ocsf`. Azure provisioning lives in `deploy/sentinel/`.

The Splunk dashboard and the Sentinel workbook remain under `integrations/` and ship
with the server. Detection rules and searches are in
[altiward-siem](https://github.com/Altiward/altiward-siem), checked against the OCSF
examples in `integrations/ocsf-examples/`. Visualisations can move there too, with
explicit producer-version compatibility. A server release can bundle a versioned export without
requiring a sibling source checkout.

The native agent protocol examples in `docs/schema/` are distinct from exported OCSF
records. Native compatibility fixtures are frozen for each supported agent minor;
keep those copies independent of the current examples.

## Build and distribution

The root Makefile coordinates all components. The root Go module builds the server;
`integrations/go.mod` allows reuse of the transport clients. The workspace and local
module replacement connect them during development. The Dockerfile builds both Go and
the console from the repository root.

`dev/` holds local Postgres and the demo seed. `deploy/compose/` holds the production
server deployment, and `deploy/azure/` the Deploy to Azure template, which runs the same
image on Azure Container Apps. Release assembly translates source paths into the established
bundle layout; see [`deploy/README.md`](../deploy/README.md).

Canonical brand SVGs live in `assets/brand/`, renderers in `scripts/brand/`, and generated
or exported copies stay with their consumers. The brand README records the outputs.
Organisation profile and website copies belong to their own repositories.

## Finding the right documentation

Use the [install guide](install.md) for operation, [data handling](data-handling.md) for
collected data and destinations, [schema documentation](schema/README.md) for native
contracts, and [releasing](releasing.md) for distribution. Each component README covers
its own build and implementation details.
