// Lets the Altiward server read the Macs Intune manages: grants a managed identity the
// Microsoft Graph application permission DeviceManagementManagedDevices.Read.All and
// nothing else. A separate template from main.bicep, because it needs the Microsoft
// Graph Bicep extension (bicepconfig.json) and a signed-in person who can grant Graph
// permissions: the Privileged Role Administrator or Global Administrator role. Deploy it
// to any resource group, with the object ID of the identity, as the install guide says.
// Compile it with `make azure-template`.

extension microsoftGraphV1

@description('The object ID (principal ID) of the managed identity to give access: the Altiward server\'s user-assigned identity, or a VM\'s system-assigned one.')
param principalId string

var permission = 'DeviceManagementManagedDevices.Read.All'

// Microsoft Graph's service principal in this tenant; 00000003-0000-0000-c000-000000000000
// is its well-known application ID.
resource graph 'Microsoft.Graph/servicePrincipals@v1.0' existing = {
  appId: '00000003-0000-0000-c000-000000000000'
}

resource grant 'Microsoft.Graph/appRoleAssignedTo@v1.0' = {
  resourceId: graph.id
  principalId: principalId
  appRoleId: filter(graph.appRoles, role => role.value == permission)[0].id
}
