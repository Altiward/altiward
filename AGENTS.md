# Working in this repo

Altiward: a Swift Mac agent plus a Go backend and React console for overseeing Mac admin
rights, open source under Apache 2.0. It works alongside SAP Privileges: Privileges grants
admin, and Altiward watches and enforces it. Altiward never grants admin itself.
The Altiward agent is what the package built from `agent/` installs on a Mac: the
`altiward-agent` daemon and `altiward-hook`, Privileges' post-change hook, which share the
`AltiwardCore` library.
Start with README.md; the agent's trust model is in agent/README.md (Design notes).

## Commands

- `make test`: Swift, Go and console unit tests (run `make console-install` once first).
  `make test-db`: adds the Postgres store suite (Docker).
- `make lint`: gofmt + go vet. CI runs both, `go test -race`, the console build,
  `make notices-check`, `make package package-verify` and `scripts/test-upgrade.sh`
  (`make test-upgrade` locally: installs a release in Docker and upgrades it).
- Admins set everything in `.env`: a new server setting gets a `${VAR:-}` line in
  `deploy/compose/compose.yaml` and an entry in `env.example`, so nobody edits
  `compose.yaml` and `upgrade.sh` can replace it. If a new server can't start without
  it, also set it in `deploy/azure/main.bicep`; optional settings are set on the
  container app after it's deployed (`deploy/azure/README.md`).
- `deploy/azure/azuredeploy.json`, which the Deploy to Azure button deploys, is compiled
  from `main.bicep`: after changing either it or its `Caddyfile`, run `make azure-template`
  (the Bicep version the Makefile names) and commit both. CI checks they match, and
  `scripts/test-azure-proxy.sh` checks the console allowlist.
- Releases: tag `agent-vX.Y.Z` for the signed agent package (`release-agent.yml`), and
  `server-vX.Y.Z` for the signed server image and deployment bundle (`release-server.yml`),
  or `server-vX.Y.Z-rc.N` for a server release candidate. Semantic versions, a minor about
  quarterly: support and agent compatibility count the last two minors, which gives sites
  about six months on a version.
  Both refuse a version without a dated section in `CHANGELOG.md`; add the user-facing
  changes there as you make them. A server tag also needs `scripts/azure-template.sh`
  run for its version. Steps: [docs/releasing.md](docs/releasing.md).
- `make notices`: regenerates `THIRD_PARTY_NOTICES.md`. Run it after adding, removing or
  upgrading a Go module or a console production dependency, and commit the result.
- `make brand-sync` refreshes the console's exported SVGs; `make brand-check` checks them.
- `make run-api` + `make console-seed` + `make console-dev`: a local stack with demo data.
- `make docs-screenshots`: regenerates the install guide's console pictures in
  `docs/images/install/`, light and dark, from the seed (run
  `npx --prefix console playwright install chromium` once). Rerun it when a console change
  alters a pictured screen.
- `make app-icon`: rebuilds `agent/packaging/AppIcon.icns`, the Installer backgrounds in
  `agent/packaging/installer/` and the square avatar (`altiward-avatar.png`, the GitHub
  organisation's picture) from the brand SVGs in `assets/brand/`. It also renders
  this repository's 1280x640 GitHub social preview, `docs/brand/social-altiward.png`
  (`scripts/brand/render-social.swift` renders the forwarder's and SIEM's too; see
  its header) with the console's fonts, so run `make console-install` once first. Rerun it
  when the logo changes.
- Swift builds use `--scratch-path ~/Library/Caches/altiward/agent-build` (the Makefile
  sets it). Never build into `agent/.build`.

## Rules

- **The event schema is a contract.** Changing an event means updating
  `docs/schema/event.schema.json`, `docs/schema/examples/*.json`, `agent/.../Event.swift`
  and `backend/internal/event/event.go` together. Both test suites decode the fixtures,
  and the Go decoder rejects unknown fields. The server must also keep accepting the
  frozen events of the last two agent releases in `docs/schema/compat/`, because sites
  upgrade the server first and roll the agent out through MDM later (see its
  README for when to add and prune them, and `OldestSupportedAgent` to match). The command wire format
  (`docs/schema/commands/`) and the signing and rotation vectors
  (`docs/schema/signature-vector.json`, `docs/schema/rotation-vector.json`) are contracts in
  the same way.
- **The hook is untrusted.** Privileges runs it as the logged-in user, who can run the
  same binary by hand with any arguments, so a hook call is a claim. Never let a
  hook-supplied value become a fact without daemon-side verification; timestamps come
  from the daemon.
- **Never drop events.** The agent outbox and the export outbox are at-least-once and
  idempotent by `event_id`. Remove an event only after it is acknowledged.
- **Privileges stays at the edge.** Altiward doesn't control Privileges, and must keep
  working when Privileges' timer is stopped or Privileges is removed. Expiry, revoke and
  the heartbeat act on the `admin` group from the daemon, never through Privileges. Only
  capturing a Privileges grant and its expiry may depend on Privileges.
- **Migrations are forever.** Sites upgrade from whatever release they run, when they
  choose, so never edit or reorder a shipped migration; add a new one. Stored session and
  device state must still decode after a change: new fields need a zero value that means
  "unknown". `TestPostgresUpgradesFromEveryMigration` upgrades from every migration with
  old-format data.
- **Console endpoints declare a role**: register them with `srv.console(auth.Viewer|Operator|Admin, …)`,
  which also enforces the CSRF token for cookie sessions. Mutations write their audit entry in the same
  transaction, with `p.Actor`; the console hides what a role can't do, but the server is the check.
- **`docs/data-handling.md` is a promise to users.** Update it in the same
  change whenever the agent collects, the server stores or keeps, or either one sends
  something new, and add a line to `CHANGELOG.md`.
- Session and device state come only from the pure reducers in `backend/internal/session`;
  both stores call them. Keep them order-independent.
- Swift 6 strict concurrency is on. Prefer `Sendable` value types and actors over
  `@unchecked Sendable`; the existing uses are lock-protected.
- Altiward is Apache 2.0 (`LICENSE`). A new dependency must use a licence on the allowlist
  in `scripts/third-party-notices.mjs`; ask before adding anything else.
- No secrets or signing material in the repo. Dev tokens live only in the Makefile.
  Local builds are signed ad hoc; release signing happens only in `release-agent.yml`, from
  repository secrets (`release-server.yml` signs keyless).
- **Console UI** keeps a macOS layout and uses the Altiward brand tokens in
  `console/src/styles.css` (never raw colours). States show a word and a glyph. Use
  sentence case, and text at 4.5:1 or better in both themes.
- Product naming: "works with SAP Privileges" only; never put SAP or Privileges in a name.

## Environment gotchas

- If `swift`/`git` fail with an Xcode license message, run `sudo xcodebuild -license accept`
  (or prefix commands with `DEVELOPER_DIR=/Library/Developer/CommandLineTools`).
- Local Postgres listens on 127.0.0.1:5433 (`docker compose`).
