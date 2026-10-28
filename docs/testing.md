# Tests, coverage and coding standards

The [contribution test policy](../CONTRIBUTING.md#test-policy) requires tests for new
features and fixes. CI runs on main and on pull requests; the main ruleset requires its
Go, Swift, console and server-image jobs, plus DCO. CI also runs fuzzing, deployment and
licence checks. Its workflow is [ci.yml](../.github/workflows/ci.yml).

## Coverage evidence

CI measures existing tests and retains `coverage-go`, `coverage-console` and
`coverage-agent` artifacts for 14 days. Keep the run URL and source commit when using a
report as badge evidence. Successful tests alone do not establish a coverage percentage.

- Go: `backend.out` and `integrations.out` are statement coverage profiles. The backend
  CI run includes Postgres store tests. Use `go tool cover -func=PROFILE` for the total,
  or `go tool cover -html=PROFILE` to inspect uncovered code.
- Console: `npm --prefix console run test:coverage` writes reports under
  `console/coverage/`, including `coverage-summary.json` and LCOV. All production `.ts`
  and `.tsx` files under `src/` are included; tests and test setup are excluded.
  Console CI requires at least 80% statement coverage.
- Agent: macOS CI runs `swift test` with `--enable-code-coverage` and saves SwiftPM's
  exported LLVM JSON. Use the production source entries when assessing coverage;
  test and generated runner code are not evidence of production coverage. LLVM line
  and region metrics must be identified as such, rather than called statement coverage.
  The first macOS report covers 27 of 31 production source files: the XPC interface,
  daemon and hook entry points are absent. Their coverage must be measured as well
  before making a claim about the complete agent.

To measure Go locally, start Postgres with `make db` and set
`ALTIWARD_TEST_DATABASE_URL` as described by `make test-db`, then run:

```sh
go test -race -count=1 -coverprofile=/tmp/altiward-backend.out ./...
cd integrations
go test -race -count=1 -coverprofile=/tmp/altiward-integrations.out ./...
```

Without the database URL, store tests are skipped and the resulting profile is not the
same as CI. On macOS, agent coverage uses the same scratch directory as the Makefile:

```sh
swift test --package-path agent --scratch-path "$HOME/Library/Caches/altiward/agent-build" --enable-code-coverage
```

Silver's 80% statement requirement remains open until current reports establish the
required production-code coverage across the project's languages. Do not exclude hard
to test production code to improve the reported number. Add tests for meaningful
behaviour, prioritizing security boundaries, failures and upgrade compatibility.

## Coding standards

Contributions must follow these standards and the repository's established naming and
layout conventions:

- Go follows [Effective Go](https://go.dev/doc/effective_go) and `gofmt`. CI rejects
  formatting differences and runs `go vet`. Keep errors explicit, preserve contexts
  and cancellation, and put state changes in the established reducers and transactions.
- Swift follows the [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/)
  and the surrounding source's four-space layout. Swift 6 concurrency checking is on.
  Prefer `Sendable` values and actors; a concurrency escape needs an explained invariant.
- TypeScript and React use the project's TypeScript configuration, explicit API models
  and existing component conventions. Use two-space indentation and the existing import
  and quotation style. Follow the console's brand, accessibility and role rules in
  [CONTRIBUTING.md](../CONTRIBUTING.md#console-ui).

Go formatting is automated. Swift and TypeScript style still need formatter selection
and CI enforcement; type checking and compilation do not satisfy that style requirement.
Review any formatter adoption separately so broad formatting changes do not hide logic
changes. Treat compiler and analyzer warnings as defects to fix, rather than suppressing
them without an explanation.
