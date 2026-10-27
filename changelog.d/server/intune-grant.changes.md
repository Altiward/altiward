- `integrations/intune/setup.sh` gives the server the Microsoft Graph permission it needs
  to read Intune, `DeviceManagementManagedDevices.Read.All`, and nothing more: to a VM's
  managed identity (`--vm`), a user-assigned one (`--identity`, including the Deploy to
  Azure app's), or a new app registration with a one-year secret (`--app`). It prints the
  `ALTIWARD_INTUNE_*` lines to add to `.env`. A Deploy to Azure template,
  `deploy/azure/intune-read.bicep`, grants the same permission to a managed identity.
