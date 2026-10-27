- When a key rotation's outcome stays unknown, `altiward-agent status` says that the Mac's
  reports wait for it, and shows the last answer that kept it waiting and when. An answer
  that may come from something between the Mac and the server, such as an HTTP 5xx, a
  timeout or a dropped connection, now says to check that the whole of `/v1/agent/`
  reaches the server, in the log and in `status`, as a refused first request already did.
  The agent keeps that answer in `agent.sqlite` only until the rotation settles
  (`docs/data-handling.md`).
