- With Intune connected, a Mac enrolling a new key is checked against Intune: the server
  looks up the device ID the agent sends (`MDMDeviceID` in the profile) and compares
  Intune's serial with the Mac's. A key sent with another Mac's ID, or the ID of a device
  that isn't a Mac, waits for approval whatever the settings, and its `agent.enrollment`
  event is High. A match never approves a key by itself: the IDs and the serial aren't
  secrets. The new `require_intune_match` setting holds every key whose check isn't a
  match; a settings update that leaves it out keeps it as it is. The event carries the
  outcome (`mdm_check`) and whether Intune knows the serial (`mdm_serial_known`, which
  counts only Macs), `GET /v1/enrollments` shows each key's `mdm_check`, and `GET /v1/mdm`
  counts the keys in use by outcome (`checks`) and those never checked (`not_checked`): a
  Mac is checked only when it enrols a new key. The device ID itself is stored but never
  shown, logged or sent. Lookups wait 10 seconds at most and are capped at 30 a minute,
  and the same key enrolling again makes none.
