- A console token's use is recorded. Its first request in each hour, to any part of the
  console or its API, adds a **Signed in** entry to Activity by the token's fingerprint,
  with the route of that request (such as `GET /v1/devices`, never the address it asked
  for), and sends it to your SIEM as an OCSF Authentication record: Low severity for a
  break-glass token, Informational otherwise. Reads in between aren't listed one by one.
  If the entry can't be written, the server refuses the request with a server error, so a
  token is never used unrecorded, and the console says it couldn't sign you in rather than
  that the token is wrong. The altiward-siem break-glass rule alerts on these sign-ins
  from altiward-siem 1.2.0.
- Single sign-on refuses anyone whose name starts with `token:` or `break-glass:`, in any
  case, so nobody can pass for a console token in Activity or the SIEM.
