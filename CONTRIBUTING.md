# Contributing to Altiward

Thank you for helping. Altiward is open source under the [Apache License 2.0](LICENSE), and
contributions are welcome: bug reports, fixes, documentation and features.

## Before you start

For anything bigger than a small fix, open an issue or start a
[Discussion](https://github.com/Altiward/altiward/discussions) first. It saves you from
building something that doesn't fit the design. The [README](README.md) is the place to
start; the rules below and the agent's [design notes](agent/README.md#design-notes)
explain the design. The [layout guide](README.md#repository-layout) and
[architecture](docs/architecture.md) show where each kind of change belongs.

## Build and test

You need macOS with Xcode or the Command Line Tools, Go 1.25 or newer, Node 22 and Docker.

```sh
make console-install   # once: console dependencies
make test              # Swift agent, Go and console unit tests
make test-db           # also runs the Postgres store suite (starts Postgres in Docker)
make lint              # gofmt and go vet
make notices           # regenerates THIRD_PARTY_NOTICES.md
```

CI runs the same checks, plus `go test -race`, the console build and a package and
upgrade test. Run `make notices` after adding, removing or upgrading a Go module or a
console production dependency, and commit the result.

To try your change against a local stack with demo data, run `make run-api`,
`make console-seed` and `make console-dev`.

## Sign off your commits (DCO)

Altiward uses the [Developer Certificate of Origin](https://developercertificate.org)
instead of a contributor licence agreement. Add a sign-off to every commit:

```sh
git commit -s -m "Fix the thing"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. It certifies that you wrote
the change, or have the right to submit it, under the project's open source licence, and
that you understand it is public. Forgot? Run `git commit --amend -s` for the last commit,
or `git rebase --signoff main` for a branch. Every commit must be signed off; we don't merge
pull requests with commits that aren't.

## The rules that keep Altiward safe to upgrade

Some things are contracts with people who already run Altiward. Please keep to them.

- **The event schema is a contract.** Changing an event means updating
  `docs/schema/event.schema.json`, `docs/schema/examples/*.json`,
  `agent/.../Event.swift` and `backend/internal/event/event.go` together. Both test suites
  decode the fixtures, and the Go decoder rejects unknown fields. The server must keep
  accepting the frozen events of the last two agent releases in `docs/schema/compat/`
  (see its README). The command wire format (`docs/schema/commands/`) and the signing
  vector (`docs/schema/signature-vector.json`) are contracts in the same way.
- **Migrations are forever.** Sites upgrade from whatever release they run, so never edit
  or reorder a shipped migration: add a new one. Stored session and device state must still
  decode after a change, so new fields need a zero value that means "unknown".
- **Never drop events.** The agent outbox and the export outbox are at-least-once and
  idempotent by `event_id`. Remove an event only after it is acknowledged.
- **`docs/data-handling.md` is a promise to users.** Update it in the same change whenever
  the agent collects, the server stores or keeps, or either sends something new, and add a
  line to `CHANGELOG.md`.
- **Dependencies stay permissively licensed.** A new dependency must use a licence on the
  allowlist in `scripts/third-party-notices.mjs`. `make notices` fails otherwise. If you
  need something else, ask in the issue first.
- **The hook is untrusted.** SAP Privileges runs it as the logged-in user, who can run
  it by hand and send the daemon anything, so a hook call is a claim. Never let a value it
  supplies become a fact without daemon-side verification: the daemon checks the `admin`
  group itself and takes its own timestamps.
- **Privileges stays at the edge.** Altiward doesn't control SAP Privileges, and must keep
  working when Privileges' timer is stopped or Privileges is removed. Expiry, revoke and
  the heartbeat act on the `admin` group from the daemon, never through Privileges; only
  capturing a Privileges grant and its expiry may depend on it.
- **No secrets or signing material** in the repository. Signing happens only in the
  release workflows: the agent's from repository secrets, the server's keyless with
  cosign.
- Console endpoints declare a role, and mutations write their audit entry in the same
  transaction. `CLAUDE.md` has the details for the backend.

## Console UI

The console keeps a macOS layout and uses the Altiward brand tokens in
`console/src/styles.css`, never raw colours. States show a word and a glyph. Use sentence
case, and keep text at 4.5:1 contrast or better in both the light and dark themes.

## Pull requests

- Keep a pull request to one change, and say in it what and why, and how you tested it.
- Add a `CHANGELOG.md` line for anything users will notice.
- Naming: say "works with SAP Privileges" and nothing else; don't put "SAP" or
  "Privileges" in a product, binary or package name.

## Reporting a security problem

Please don't open a public issue. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/Altiward/altiward/security)
(the Security tab, then "Report a vulnerability").
