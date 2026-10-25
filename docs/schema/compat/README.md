# Agent compatibility fixtures

Admins upgrade the server first, then roll the agent out through MDM at their own pace.
The server must accept events from agents up to two minor versions older than itself.

Each directory holds the events one agent release sends, frozen when that release ships:
`agent-0.1/` is what agent 0.1.x sends. The backend's tests post every file in every
directory to the API and require all of them to be accepted.

- **When an agent release ships** with a new minor version, copy `../examples/` here as
  `agent-X.Y/`, leaving out `agent-silent.json` and `agent-enrollment-*.json`, which only
  the server raises.
- **Keep the newest two** directories, the new release's included, and delete the rest.
  Set `OldestSupportedAgent` in `backend/internal/release` to the oldest one kept: the
  console tags Macs running anything older, and a test fails if the two disagree.
- **Never edit a directory** after it's frozen. If a test fails on one, the server broke
  compatibility: fix the server, not the fixture.
