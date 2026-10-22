# Repository tools

Run these from the repository root, or use the corresponding Make target.

| Tool | Purpose |
| --- | --- |
| [`server-bundle.sh`](server-bundle.sh) | Assemble the deployment archive, templates, SIEM content and notices |
| [`release-notes.sh`](release-notes.sh) | Extract and validate a component's changelog section |
| [`test-upgrade.sh`](test-upgrade.sh) | Install and upgrade a server in disposable Docker resources |
| [`azure-template.sh`](azure-template.sh) | Move the Deploy to Azure template, and its buttons, to a server release |
| [`test-azure-proxy.sh`](test-azure-proxy.sh) | Check the Deploy to Azure template's console allowlist in Docker |
| [`agent-smoke.mjs`](agent-smoke.mjs) | Act as one Mac against a running server: enroll, a signed event and a long poll |
| [`third-party-notices.mjs`](third-party-notices.mjs) | Generate or check shipped dependency notices and the licence allowlist |
| [`brand/generate.sh`](brand/generate.sh) | Render committed app icons, Installer backgrounds, avatars and the social preview on macOS |
| [`brand/export.sh`](brand/export.sh) | Export canonical assets to an explicit consumer directory, or check its copies |

`make app-icon`, `make brand-sync`, `make brand-check`, `make notices`,
`make notices-check` and `make azure-template` expose the common operations. Brand sources and output ownership
are documented in [`assets/brand/`](../assets/brand/).

Development services and seeding live in [`dev/`](../dev/), Azure provisioning in
[`deploy/sentinel/`](../deploy/sentinel/), and Mac package installation scripts in
[`agent/packaging/`](../agent/packaging/).

The Sentinel workbook also has a generated ARM template. Edit
`integrations/sentinel/workbook.json`, then run:

```sh
go test ./integrations/sentinel -run Workbook -update
```

Commit both JSON files. The normal integration test run checks that the generated
template matches its source.
