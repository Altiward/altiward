- With Intune connected, a Mac whose agent stopped reporting is reported within hours
  (#30). When Intune hears from a Mac at least 2 hours after its last check-in with
  Altiward, the server raises its `agent.silent` alert at once with `basis`
  `mdm_check_in`, at High: the agent may have been removed or stopped. A closed laptop
  stays quiet, as Intune doesn't hear from it either, and the alert limit still applies to
  every Mac (`basis` `no_contact`, Medium). A silence is raised once on either basis. The
  early alert applies to Macs whose agent has ever reported 1.2.0 or later, waits 2 hours
  and 10 minutes after the server starts, and waits a day for a Mac with a new key held for
  approval. While more than the larger of 5 and a fifth of the Macs in Intune meet the
  rule, counting those raised already and leaving out Macs Altiward hasn't heard from for
  a day, none is raised early: Altiward itself is then probably unreachable. The server
  logs a warning at most hourly, and **Settings › MDM** shows a banner for a day.
  **Fleet** says which basis raised a Mac's alert.
- `agent.silent` gains `basis`, `admin_members` (who was in the Mac's admin group at its
  newest health reading), and with Intune connected `mdm_last_check_in` (Intune's last
  check-in from the Mac) and `pending_device_id` (a key waiting for approval for over a
  day). The admins and Intune's check-in are new to the SIEM, and `docs/data-handling.md`
  says so. The OCSF finding's description names the admins on both bases.
