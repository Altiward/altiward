- The server can read the Macs Microsoft Intune manages, through Microsoft Graph, with the
  `DeviceManagementManagedDevices.Read.All` application permission and nothing more. Set
  `ALTIWARD_INTUNE_AUTH` to `secret`, `certificate` or `managed-identity`, with
  `ALTIWARD_INTUNE_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET` or `_CERTIFICATE_FILE` as for
  the Sentinel export. It needs a server whose tokens name one tenant.
- With Intune connected, the server keeps a copy of its Macs, refreshed every 15 minutes:
  each Mac's serial number, name, primary user, last check-in, and Intune and Entra ID
  device IDs. A sync that fails keeps the last good copy. Turning Intune off deletes the copy at
  the server's next start. `GET /v1/mdm` shows the sync, and `GET /v1/mdm/devices` lists
  the Macs for every console role, without their device IDs. `altiward-api diagnose`
  checks the connection, and reports a sync that is failing or hasn't succeeded for an
  hour.
