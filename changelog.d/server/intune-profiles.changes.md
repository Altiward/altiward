- The server bundle's `profiles/` has `com.altiward.agent.mobileconfig`, the agent
  settings as a ready-made profile with the same keys and values as the example plist.
  Intune takes it, and `altiward-login-items.mobileconfig`, as Custom profiles with no
  editing of the file beforehand.
- `integrations/intune/Push-AltiwardProfiles.ps1` creates the agent settings, login items
  and (with the agent release's `corp.sap.privileges.mobileconfig`) SAP Privileges
  profiles in Intune and assigns them to a group, signed in as you rather than as the
  server, which never writes to Intune. It checks the files before it signs in, updates
  profiles of the same name on a second run, keeps each profile's existing assignments, and
  with `-WhatIf` writes nothing.
