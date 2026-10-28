- The agent sends the MDM's ID for the Mac when it enrols, if the profile sets
  `MDMDeviceID` (Intune fills in `{{deviceid}}`), so the server can check the Mac against
  the MDM's list. `HeartbeatInterval` is now capped at 3600 seconds, so a running agent
  checks in at least hourly.
