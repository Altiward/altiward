Upgrade every replica of the server to this version, and don't run an older one on the
same database afterwards: an older server doesn't know `agent.admin_group`, so it drains
that event from the outbox unsent, and the SIEM never gets it. Every replica also needs
the same SIEM settings, because a replica without a SIEM stores events without queuing
them for it, and what may be removed depends on which SIEMs the server has. The upgrade
runs one migration, 0008, that adds indexes on `events` and `export_outbox`. It can take
a while on a large database, and ingest waits until it finishes. A server with a SIEM
connected gets the default history period of one year on upgrade: set **Keep history
for** if you want something else. History from before the SIEM was connected is kept
until you send it with `replay-exports` (Connect your SIEM, in `docs/install.md`), which
moves the date back to where the replay starts. When the server first starts, it sends
each Mac's admin group from the health readings it already holds, once. Expiry begins at
its next daily run after that has finished, so no admin group history is lost to it.
During a rolling update, a health reading that an older server stores after the migration
is neither backfilled nor raised, so the SIEM's admin group record can miss a change that
began and ended inside the update window; the new server sends each Mac's current group
with its first reading.
