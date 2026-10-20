# Command wire format

The agent ↔ API contract for remote commands.
Both test suites decode these fixtures, so change them together with
`agent/Sources/AltiwardCore/Commands.swift` and `backend/internal/command`.

| File | What |
| --- | --- |
| [`agent-commands.json`](agent-commands.json) | Response to `GET /v1/agent/commands`. With `?wait=N` (whole seconds, 0 to 50) the server holds the request until a command is queued or N seconds pass, then answers with the same shape, possibly empty |
| [`command-result.json`](command-result.json) | Body of `POST /v1/agent/commands/{id}/result` |

## Result

| Field | Meaning |
| --- | --- |
| `status` | `completed` (something was revoked and nothing failed), `failed` (any user failed, or `error` is set) or `skipped` (nothing to do) |
| `error` | Command-level failure, such as `unsupported command`; otherwise null |
| `revoked` | Users removed from the `admin` group |
| `failed` | `[{user, error}]`: users still admin after the attempt |
| `skipped` | `[{user, reason}]`. `reason` is `permanent_admin`, `not_admin` or `session_ended` |
| `completed_at` | When the agent finished, by the agent's clock |
