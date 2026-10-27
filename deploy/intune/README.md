# Let the server read Intune

[`setup.sh`](setup.sh) grants a managed identity, or a new app registration, Microsoft
Graph's `DeviceManagementManagedDevices.Read.All` application permission, then prints the
settings for Altiward's `.env`. That is the only access it gives: read access to the
devices Intune manages, and nothing it could change. It needs someone who can grant Graph
permissions (Privileged Role Administrator or Global Administrator), and it asks before it
changes anything.

The [install guide](../../docs/install.md#7-connect-intune-optional) covers what the
server reads, the three ways to grant the permission, the settings and troubleshooting.
From a source checkout, run one of:

```sh
bash deploy/intune/setup.sh --vm <resource group>/<vm name>
bash deploy/intune/setup.sh --identity <client ID>
bash deploy/intune/setup.sh --app "Altiward Intune"
```

The server release bundle ships the script at `integrations/intune/setup.sh`. The
Deploy to Azure template for the same grant is
[`deploy/azure/intune-read.bicep`](../azure/intune-read.bicep), compiled to
`intune-read.json` by `make azure-template`.

## Upload Altiward's profiles to Intune

[`Push-AltiwardProfiles.ps1`](Push-AltiwardProfiles.ps1) creates Altiward's Mac profiles in
Intune and assigns them to a group, in one command. It is the alternative to making each
profile by hand in the admin center ([Deploy the agent](../../docs/install.md#2-deploy-the-agent)).
It runs as you, signed in with your own account: the Altiward server never writes to
Intune, and this script is the only thing here that does.

You need PowerShell 7 and the Microsoft Graph module, and an account that can create
configuration profiles and assign them (Intune Administrator, or a role with the same
rights):

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

First copy `com.altiward.agent.mobileconfig` from the server bundle's `profiles/` and edit
its `ServerURL`, `EnrollmentToken`, `PermanentAdmins` and `HookCodeRequirement`, as the
install guide describes.
Leave `MDMDeviceID` as `{{deviceid}}`: Intune fills in each Mac's device ID. Then run it
with `-WhatIf` first, and again without it:

```powershell
./Push-AltiwardProfiles.ps1 -AgentSettings ./com.altiward.agent.mobileconfig `
    -PrivilegesSettings ./corp.sap.privileges.mobileconfig -Group 'Altiward pilot' -WhatIf
```

| Parameter | |
| --- | --- |
| `-AgentSettings` | Required. Your edited `com.altiward.agent.mobileconfig`. |
| `-Group` | Required. The display name of the Entra group to assign the profiles to. Start with a pilot group. |
| `-PrivilegesSettings` | `corp.sap.privileges.mobileconfig` **from the agent release you are deploying**, whose checksum matches that release's hook. Leave it out if Privileges already has a profile: add the keys to that one. |
| `-LoginItems` | `altiward-login-items.mobileconfig`. It finds the one in this repository's `deploy/mdm`, or the server bundle's `profiles/`, without it. Both it and the agent settings name `TEAMID`, the Developer ID team that signs the agent: replace it in your copies first. The script doesn't check that. |
| `-ClientId` | The application (client) ID of your own app registration to sign in with. See below. |
| `-NoDeviceID` | Don't require `MDMDeviceID` to be `{{deviceid}}`. |
| `-WhatIf` | Look everything up and say what it would do, writing nothing. |

What it does, in order:

1. Checks the files before it signs in. It stops if `ServerURL` or `EnrollmentToken` is
   still the example, if `MDMDeviceID` isn't `{{deviceid}}`, or if the Privileges file's
   checksum is still the placeholder.
2. Signs you in (a browser window) for `DeviceManagementConfiguration.ReadWrite.All` and
   `Group.Read.All`.
3. Looks up the group and each profile by display name: `Altiward: agent settings`,
   `Altiward: login items` and `Altiward: settings for SAP Privileges`. It stops, having
   changed nothing, if no group or several have that name, or if two profiles do.
4. Creates each profile as a **macOS Custom profile** on the device channel, carrying the
   file exactly as it is, or updates the profile of that name. Run it again after editing a
   file and the profile is updated, not duplicated. Don't rename these profiles in
   Intune: the script finds them by name.
5. Adds the group to each profile's assignments. Every assignment a profile already has
   stays, exclusions included.

It never deletes anything and never changes a profile that has another name.

### `-ClientId`

Without it, `Connect-MgGraph` signs in through *Microsoft Graph Command Line Tools*, an app
Microsoft owns and every tenant shares. The first sign-in asks you to consent to the two
permissions above. Consent for yourself only. If you tick **Consent on behalf of your
organisation**, the permission to manage configuration profiles is granted to that shared
app for every user in the tenant, which is broader than one script run needs. (What each
person can then do is still limited by their own Intune role.)

To avoid that, register your own app in **Entra ID › App registrations**: single tenant,
platform **Mobile and desktop applications** with the redirect URI `http://localhost`, and
the delegated Graph permissions `DeviceManagementConfiguration.ReadWrite.All` and
`Group.Read.All`. Consent for it, then pass its application (client) ID as `-ClientId`.
Delete the registration when you are done if you won't run the script again.

The server release bundle ships the script and its module at `integrations/intune/`.

Tests are colocated here. `setup_test.go` uses `testdata/fake-az.sh`, a fake CLI, and makes
no Azure requests: run `go test ./deploy/intune` from the repository root.
`AltiwardIntune.Tests.ps1` tests the script's functions with Pester 5 and a mocked Graph,
and never signs in: run `pwsh -c 'Invoke-Pester deploy/intune -CI'`.
