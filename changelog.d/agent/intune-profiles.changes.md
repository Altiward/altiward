- The agent release carries the SAP Privileges keys as a ready-made profile too,
  `corp.sap.privileges.mobileconfig`, pinned to that release's hook like
  `corp.sap.privileges.plist` and in its `SHA256SUMS`. Intune takes it as a Custom
  profile. The example `com.altiward.agent.plist` gains `MDMDeviceID`, the MDM's own ID
  for the Mac (`{{deviceid}}` for Intune); the agent ignores it for now.
