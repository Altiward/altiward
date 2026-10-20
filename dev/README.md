# Local development

This directory holds development-only services and demo data. Start from the repository
root:

```sh
make db             # Postgres on 127.0.0.1:5433
make run-api        # API on 127.0.0.1:8080 with development tokens
make console-seed   # another terminal: simulated Macs and sessions
make console-dev    # console on localhost:5173
```

`compose.yaml` starts only Postgres. `seed.mjs` uses Node's built-in modules to enroll
simulated Macs and post signed events through the real agent protocol; it has no console
package dependencies. Development tokens are defined in the Makefile and seed script.

`make db-down` stops the development database. The Compose project is named `altiward`;
the production deployment is a separate project named `altiward-server`.

For production, use [`deploy/compose/`](../deploy/compose/) and the
[install guide](../docs/install.md).

## VS Code

Open the application repository root and install the recommended Swift extension.
`.vscode/` contains build tasks and debug configurations for the agent and hook, with
build products in `~/Library/Caches/altiward/agent-build/`. Agent configurations run
`status` against local development state by default; change the arguments for the
command you are investigating. Hook configurations need a running daemon to receive
their XPC message.
