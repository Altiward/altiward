- Revoking a Mac's only active key, with no key waiting for approval, now retires the Mac
  (#171). A retired Mac leaves **Fleet** and the Overview's Mac figures, never raises a
  "not checking in" alert, and shows under **Show › Retired** with when it was retired and
  when its history is removed. The revoke asks you to confirm, and warns if someone still
  has admin rights on the Mac or it is failing an integrity check. A person with an open
  session on a retired Mac stays in **Admins now**, tagged **Mac retired**. A retired
  Mac's failing check no longer counts in the Overview, but shows on the Mac under
  **Show › Retired** in **Fleet**. A new key for the Mac brings it back, and so does an
  alert that one of its replaced keys was used again. Macs you had already revoked this
  way are retired when the server first starts.
- **Keep history for**, in **Settings › General** (`history_days` in the settings API),
  sets how long Altiward keeps events, ended elevation sessions, commands and Macs that
  stopped checking in. The default is one year when a SIEM is connected and for good when
  none is. You can set 90 to 3650 days, or keep history for good. Once a day the server
  removes what is older, with each Mac that stopped checking in for longer than the period
  and its sessions, events and commands. It revokes the Mac's keys first, so a Mac that
  comes back enrols again. It never removes an event a SIEM is waiting for, anything from
  the last 90 days (Postgres refuses to delete it), or, under the default period, anything
  received before the SIEM's coverage date. That date is an hour after the first start of
  this version with the SIEM configured, so on a server that already sends to a SIEM it is
  the upgrade, until you replay earlier history with `replay-exports`. Removing a SIEM's
  settings and restoring them later starts its coverage again, an hour after the start
  that restores them, and `drop-exports` forgets it. `GET /v1/retention` reports the
  period in force and why. Activity records each run as `expire_history` and each Mac
  removed as `remove_device`, with the actor `altiward:server`.
- The server raises an `agent.admin_group` event of its own, so your SIEM keeps who was in
  each Mac's admin group after the health readings that recorded it expire. It is sent
  when the group changes, and as a snapshot for a Mac's first reading and once a day for
  each Mac in use. It reaches the SIEM as OCSF Group Management (3006) records: one for
  each person who joined, left or is in the group, and one for the Mac. Expect about one
  record for each admin on each Mac every day, one for each Mac every day, and four for
  each elevation. It is a record, not a detection. An hour after the server first starts,
  a one-off job raises these events from the readings already stored. Agents can't send
  this type, and the Agent versions panels of the Splunk dashboard and the Sentinel
  workbook leave it out, as they do `agent.enrollment` and `agent.silent`.
- A new migration (0008) adds the indexes expiry needs, and a floor in the database that
  refuses to delete events, sessions, commands or Macs from the last 90 days, or to change
  when an event was received or a command created.
- Events are no longer the full history once expiry runs: state must never be rebuilt from
  them. `docs/data-handling.md` says what is kept and for how long.
