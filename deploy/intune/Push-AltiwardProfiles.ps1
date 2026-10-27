#Requires -Version 7.0
<#
.SYNOPSIS
Uploads Altiward's Mac profiles to Intune and assigns them to a group, as you.

.DESCRIPTION
Creates the agent settings, the login items and (when given) the SAP Privileges settings
as macOS Custom profiles in Intune, or updates the ones of the same name, and assigns each
to the group. It signs in with your own account (Connect-MgGraph) and asks for
DeviceManagementConfiguration.ReadWrite.All and Group.Read.All; the Altiward server never
writes to Intune. It checks the files before it signs in, and looks up every name before it
writes anything. Existing assignments, exclusions included, are kept. -WhatIf writes nothing.

.PARAMETER AgentSettings
Your edited com.altiward.agent.mobileconfig, with its ServerURL and EnrollmentToken set.

.PARAMETER LoginItems
altiward-login-items.mobileconfig. Defaults to the one beside this script's source tree
(../mdm), or else the server bundle's (../../profiles).

.PARAMETER PrivilegesSettings
corp.sap.privileges.mobileconfig from the agent release, with its checksum filled in. Leave
it out if your Privileges profile already exists: add the keys to that instead.

.PARAMETER Group
The display name of the Entra group the profiles go to. Start with a pilot group.

.PARAMETER ClientId
The application (client) ID of your own app registration to sign in with, instead of
Microsoft's Graph Command Line Tools app. See README.md.

.PARAMETER NoDeviceID
Don't require MDMDeviceID to be {{deviceid}}, for a profile you've changed on purpose.

.EXAMPLE
./Push-AltiwardProfiles.ps1 -AgentSettings ./com.altiward.agent.mobileconfig -Group 'Altiward pilot' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$AgentSettings,
    [string]$LoginItems,
    [string]$PrivilegesSettings,
    [Parameter(Mandatory)][string]$Group,
    [string]$ClientId,
    [switch]$NoDeviceID
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AltiwardIntune.psm1') -Force

if (-not $LoginItems) {
    $LoginItems = @(
        Join-Path $PSScriptRoot '../mdm/altiward-login-items.mobileconfig'
        Join-Path $PSScriptRoot '../../profiles/altiward-login-items.mobileconfig'
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $LoginItems) { throw "Can't find altiward-login-items.mobileconfig. Give its path with -LoginItems." }
}

# Check the files first: a mistake shouldn't cost a sign-in.
$plan = Get-AltiwardProfilePlan -AgentSettings $AgentSettings -LoginItems $LoginItems `
    -PrivilegesSettings $PrivilegesSettings -NoDeviceID:$NoDeviceID

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'The Microsoft Graph PowerShell module is missing. Install it, then run this again: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}

$connect = @{ Scopes = @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All'); NoWelcome = $true }
if ($ClientId) { $connect.ClientId = $ClientId }
Connect-MgGraph @connect | Out-Null
try {
    # A module function doesn't see this script's -WhatIf and -Confirm, so pass them on.
    $done = @(Publish-AltiwardProfiles -Profiles $plan -Group $Group `
            -WhatIf:$WhatIfPreference -Confirm:($ConfirmPreference -eq 'Low'))
} finally {
    Disconnect-MgGraph | Out-Null
}

foreach ($d in $done) { Write-Host "$($d.Action) '$($d.Name)' and assigned it to '$Group'." }
if ($done) { Write-Host "Intune sends them to the Macs in '$Group' at their next check-in." }
