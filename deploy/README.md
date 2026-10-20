# Deployment

| Directory | Purpose |
| --- | --- |
| [`compose/`](compose/) | Production server, Postgres and Caddy; environment template and upgrade script |
| [`mdm/`](mdm/) | Mac configuration templates for the Altiward agent and SAP Privileges |
| [`sentinel/`](sentinel/) | Azure resource provisioning for the Sentinel export |

Start with the [install guide](../docs/install.md). Development services live in
[`dev/`](../dev/).

The server release bundle preserves its installation layout: server files are in
`deploy/compose/`, the agent's Mac templates in `profiles/`, and the Sentinel script in
`integrations/sentinel/setup.sh`. [`scripts/server-bundle.sh`](../scripts/server-bundle.sh)
assembles that layout from these sources. The signed agent release supplies the
Privileges profile whose checksum matches its package; the server bundle doesn't
include it.
