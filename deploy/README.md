# Deployment

| Directory | Purpose |
| --- | --- |
| [`compose/`](compose/) | Production server, Postgres and Caddy; environment template and upgrade script |
| [`azure/`](azure/) | The Deploy to Azure template: the server on Azure Container Apps, with Postgres on a private network and its tokens in Key Vault |
| [`mdm/`](mdm/) | Mac configuration templates for the Altiward agent and SAP Privileges |
| [`sentinel/`](sentinel/) | Azure resource provisioning for the Sentinel export |
| [`intune/`](intune/) | The script that grants the server read access to Intune, whose Deploy to Azure template is [`azure/intune-read.bicep`](azure/intune-read.bicep), and the script that uploads Altiward's Mac profiles to Intune |
| [`caddy/`](caddy/) | The patched, digest-pinned Caddy image that Compose and Azure use, and how to rebuild it |

Start with the [install guide](../docs/install.md). Development services live in
[`dev/`](../dev/).

The server release bundle preserves its installation layout: server files are in
`deploy/compose/`, the agent's Mac templates in `profiles/`, and the Sentinel and Intune scripts in
`integrations/sentinel/setup.sh` and `integrations/intune/setup.sh`. [`scripts/server-bundle.sh`](../scripts/server-bundle.sh)
assembles that layout from these sources. The signed agent release supplies the
Privileges profile whose checksum matches its package; the server bundle doesn't
include it.
