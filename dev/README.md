# Local development

This directory holds development-only services and demo data.

## Try the console with demo data

You need only Docker with Compose v2: Docker Desktop on macOS or Windows, or Docker
Engine and the `docker-compose-plugin` package on Linux. On Windows, run the commands
in WSL 2 with Docker Desktop's WSL integration turned on.

```sh
git clone https://github.com/Altiward/altiward
cd altiward
docker compose -f dev/compose.demo.yaml up --build    # or: make demo
```

The first run downloads images and builds the server, which can take a few minutes. When
the output says `Demo ready`, open http://localhost:8080 and sign in with the token
`dev-console-token-001`. The demo keeps running after the command returns;
`docker compose -f dev/compose.demo.yaml down -v` (or `make demo-down`) stops it and
deletes its data.

`compose.demo.yaml` builds the production image from your checkout, runs it with its own
Postgres, and fills it with `seed.mjs`. Nothing is published outside `127.0.0.1:8080`.

## Run from source

You need Go 1.27+, Node 22.12+, Docker with Compose v2 and `make`. Start from the repository
root:

```sh
make console-install   # once: console dependencies
```

```sh
make run-api        # Postgres on 127.0.0.1:5433 and the API on 127.0.0.1:8080; leave it running
```

```sh
make console-seed   # in a second terminal: simulated Macs and sessions
make console-dev    # console on localhost:5173; sign in with dev-console-token-001
```

`compose.yaml` starts only Postgres. `seed.mjs` uses Node's built-in modules to enroll
simulated Macs and post signed events through the real agent protocol; it has no console
package dependencies. Development tokens are defined in the Makefile and seed script.
Check-ins are timed by the server's clock, so to seed a Mac that stopped checking in it
backdates that device in this Compose project's Postgres (`docker compose exec`); the
monitor then raises `agent.silent` within a minute.

`make db-down` stops the development database. The Compose project is named `altiward`;
the demo is `altiward-demo` and the production deployment `altiward-server`.

For production, use [`deploy/compose/`](../deploy/compose/) and the
[install guide](../docs/install.md).

## Troubleshooting

| You see | What to do |
| --- | --- |
| `unknown shorthand flag: 'f' in -f` | Docker is installed without Compose v2. Install Docker Desktop, or the `docker-compose-plugin` package |
| `permission denied while trying to connect to the Docker daemon socket` | On Linux, add yourself to the `docker` group (`sudo usermod -aG docker $USER`), then sign out and back in |
| `Cannot connect to the Docker daemon` | Start Docker Desktop, or the Docker service |
| `make: command not found` | Install `make` (`sudo apt install make` on Ubuntu), or use the `docker compose` commands above |
| `does not provide an export named 'styleText'` when the console starts | Node is too old: install Node 22.12 or newer. Ubuntu 24.04's `nodejs` package is 18 |
| `invalid go version '1.27.0': must match format 1.23` | Go is older than 1.21: install Go 1.27. Ubuntu 22.04's `golang-go` package is 1.18 |
| `address already in use` or `port is already allocated` for 8080 | Something else is on port 8080, such as `make run-api` or the demo. Stop it, or the demo with `make demo-down` |
| `Can't reach the API at http://127.0.0.1:8080` from `make console-seed` | Start `make run-api` in another terminal and leave it running |
| Nothing at `localhost:5173` | `make console-dev` hasn't started: it runs only after `make console-seed` succeeds |

## VS Code

Open the application repository root and install the recommended Swift extension.
`.vscode/` contains build tasks and debug configurations for the agent and hook, with
build products in `~/Library/Caches/altiward/agent-build/`. Agent configurations run
`status` against local development state by default; change the arguments for the
command you are investigating. Hook configurations need a running daemon to receive
their XPC message.
