# Docker Compose deployment

The example deployment for one organisation: the Altiward server, Postgres, and Caddy
for TLS. Follow the [install guide](../../docs/install.md). It ships in each server
release on [GitHub Releases](https://github.com/Altiward/altiward/releases). The image,
`ghcr.io/altiward/altiward-api`, is public: Docker pulls it without a login.

| File | |
| --- | --- |
| `compose.yaml` | The three services. Nothing but Caddy publishes a port. Settings come from `.env`, so you needn't edit it. |
| `Caddyfile` | Two sites: the agent hostname passes only `/v1/agent/*`; the console hostname only answers the networks in `ALTIWARD_CONSOLE_ALLOW`. |
| `env.example` | Every setting, to copy to `.env` |
| `upgrade.sh` | Upgrades to a new release from its files: checks, backs up, loads, restarts |
| `certs/` | Your own TLS certificates for Caddy, or a CA file for the syslog receiver |
| `.altiward/` | The files as the release shipped them, so `upgrade.sh` can tell which you changed |

The project is named `altiward-server`, so it doesn't collide with the repository's
development `dev/compose.yaml`.
