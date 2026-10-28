- The installed agent takes its settings from the `com.altiward.agent` payloads of the
  profiles MDM installed, as the Mac's `/usr/bin/profiles` reports them, instead of the
  preferences. An admin could write `/Library/Managed Preferences` and macOS reported the
  written values as set by MDM, so they could point the agent at another server or change
  its policy unnoticed. The agent keeps the last settings it read for when the profiles
  can't be read, and on first start waits until they can. A Mac not enrolled in MDM takes
  the settings from the preferences and fails `settings_managed`. `ALTIWARD_*` environment
  overrides now apply only in development.
- `settings_managed` compares the managed preferences files for `com.altiward.agent` and
  `corp.sap.privileges` with MDM's payloads, both ways,
  on every heartbeat and whenever one of the files changes: the device's files, and the
  folders of people signed in at the login window. A changed, removed or added key fails
  it, naming the key, never its value, and it is reported `failed` again when the failing
  keys change, at most every 10 minutes. The agent's own use of Privileges' settings
  (expiry, the checks) also comes from MDM's payloads.
