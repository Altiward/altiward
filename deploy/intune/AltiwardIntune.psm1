# Functions behind Push-AltiwardProfiles.ps1. They live here so the tests can import them
# without running the script, and mock Invoke-AltiwardGraph, the only function that talks
# to Microsoft Graph. Nothing here signs in: the script does that, as the admin.

$script:GraphRoot = 'https://graph.microsoft.com/beta'

# Names the profiles are given in Intune. Uploading again finds each by its name and updates
# it, so changing a name makes the next upload create a second profile.
$script:AgentProfileName = 'Altiward: agent settings'
$script:LoginItemsProfileName = 'Altiward: login items'
$script:PrivilegesProfileName = 'Altiward: hook and elevation settings'

# The example values in com.altiward.agent.mobileconfig that must be replaced.
$script:ExampleServerURL = 'https://api.altiward.example'
$script:ExampleEnrollmentToken = 'REPLACE_WITH_TENANT_AGENT_TOKEN'
$script:ChecksumPlaceholder = 'REPLACE_WITH_SHA256_OF_SIGNED_HOOK'

# The string Intune's Custom profiles replace with the Mac's Intune device ID.
$script:IntuneDeviceID = '{{deviceid}}'

# The value of a key in a profile's settings payload (its first payload), as text, or $null
# when the key isn't there.
function Get-PayloadValue([xml]$Mobileconfig, [string]$Key) {
    $payload = $Mobileconfig.SelectSingleNode("/plist/dict/key[.='PayloadContent']/following-sibling::array[1]/dict[1]")
    if (-not $payload) { throw 'This is not a configuration profile: it has no PayloadContent.' }
    $value = $payload.SelectSingleNode("key[.='$Key']/following-sibling::*[1]")
    if ($value) { $value.InnerText }
}

# Throws unless the agent settings profile is ready to upload: ServerURL and EnrollmentToken
# are yours, and MDMDeviceID is what Intune fills in (unless -NoDeviceID).
function Test-AgentProfile([xml]$mobileconfig, [switch]$NoDeviceID) {
    foreach ($example in @(@('ServerURL', $script:ExampleServerURL), @('EnrollmentToken', $script:ExampleEnrollmentToken))) {
        $key, $exampleValue = $example
        $value = Get-PayloadValue $mobileconfig $key
        if ([string]::IsNullOrWhiteSpace($value) -or $value -ceq $exampleValue) {
            throw "${key}: Still the example value. Edit it in the agent settings profile first."
        }
    }
    if (-not $NoDeviceID) {
        $id = Get-PayloadValue $mobileconfig 'MDMDeviceID'
        if ($id -cne $script:IntuneDeviceID) {
            throw "MDMDeviceID must be $($script:IntuneDeviceID) (as shipped; Intune fills in each Mac's device ID). Use -NoDeviceID to leave it as it is."
        }
    }
}

# Throws unless the Privileges profile carries a hook checksum, as the agent release's copy
# does. The copy in the source tree has a placeholder, and Privileges refuses a hook whose
# checksum doesn't match.
function Test-PrivilegesProfile([xml]$mobileconfig) {
    $sum = Get-PayloadValue $mobileconfig 'PostChangeExecutableChecksum'
    if ($sum -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'PostChangeExecutableChecksum is not a SHA-256 yet: use the file from the agent release, which pins the checksum of its signed hook.'
    }
}

# The Graph body for a macOS custom profile that carries the file's bytes unchanged.
function New-ConfigurationBody($displayName, [byte[]]$payloadBytes, $fileName) {
    @{
        '@odata.type'     = '#microsoft.graph.macOSCustomConfiguration'
        displayName       = $displayName
        description       = 'Uploaded by Altiward''s Push-AltiwardProfiles.ps1.'
        payloadName       = $displayName
        payloadFileName   = $fileName
        payload           = [Convert]::ToBase64String($payloadBytes)
        deploymentChannel = 'deviceChannel'
    }
}

# One request to Microsoft Graph's beta endpoint, as the signed-in admin. $Path starts with
# a slash. Returns what Graph answers, which for objects is a hashtable.
function Invoke-AltiwardGraph($Method, $Path, $Body) {
    $request = @{ Method = $Method; Uri = "$($script:GraphRoot)$Path" }
    if ($null -ne $Body) {
        $request.Body = ConvertTo-Json -InputObject $Body -Depth 10
        $request.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @request
}

# $filter for a display name: a quote in the name is doubled, then the whole is URL-encoded.
function Get-NameFilter($name) {
    '$filter=' + [uri]::EscapeDataString("displayName eq '$($name.Replace("'", "''"))'") + '&$select=id,displayName'
}

# The ID of the one group with this display name. Throws when there is none or several.
function Resolve-OneGroup($name) {
    $found = @((Invoke-AltiwardGraph 'GET' ('/groups?' + (Get-NameFilter $name)) $null).value | Where-Object { $_ })
    if ($found.Count -eq 0) { throw "No group named '$name'. Give the group's display name exactly." }
    if ($found.Count -gt 1) { throw "More than one group named '$name' ($($found.Count) found). Rename one, or give a group with a unique name." }
    $found[0].id
}

# The ID of the one configuration profile with this display name, or $null when there is
# none. Throws when several have it: it can't tell which to update.
function Resolve-OneConfiguration($name) {
    $path = '/deviceManagement/deviceConfigurations?' + (Get-NameFilter $name)
    $found = @((Invoke-AltiwardGraph 'GET' $path $null).value | Where-Object { $_ })
    if ($found.Count -gt 1) { throw "More than one configuration profile named '$name' ($($found.Count) found). Delete or rename the extras in Intune and run it again." }
    if ($found.Count -eq 1) { $found[0].id }
}

# Assigns the profile to the group, keeping every assignment it has already, exclusions
# included: /assign replaces the whole list. Does nothing if the group is already assigned.
# Returns $true when it changed the assignments.
function Add-Assignment($configurationId, $groupId) {
    $included = '#microsoft.graph.groupAssignmentTarget'
    $base = "/deviceManagement/deviceConfigurations/$configurationId"
    $targets = @((Invoke-AltiwardGraph 'GET' "$base/assignments" $null).value | Where-Object { $_ -and $_.target } | ForEach-Object { $_.target })
    if ($targets | Where-Object { $_['@odata.type'] -eq $included -and $_.groupId -eq $groupId }) { return $false }
    $targets += @{ '@odata.type' = $included; groupId = $groupId }
    $body = @{ assignments = @($targets | ForEach-Object { @{ target = $_ } }) }
    $null = Invoke-AltiwardGraph 'POST' "$base/assign" $body
    $true
}

# Reads and checks the files, with no request to Microsoft, and returns what to upload:
# the agent settings, the login items, and the Privileges settings when given.
function Get-AltiwardProfilePlan {
    param(
        [Parameter(Mandatory)][string]$AgentSettings,
        [Parameter(Mandatory)][string]$LoginItems,
        [string]$PrivilegesSettings,
        [switch]$NoDeviceID
    )
    function Read-Profile($path, $displayName, $what) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Can't find the $what file: $path" }
        $bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $path).Path)
        # Load from the bytes, not a string: a byte order mark (Notepad and Windows PowerShell 5.1
        # add one) is then read as one, and the bytes sent to Intune stay as they are.
        try {
            $xml = [xml]::new()
            $stream = [IO.MemoryStream]::new($bytes)
            try { $xml.Load($stream) } finally { $stream.Dispose() }
        }
        catch { throw "The $what file isn't a profile (it isn't valid XML): $path" }
        [pscustomobject]@{ DisplayName = $displayName; FileName = Split-Path -Leaf $path; Bytes = $bytes; Xml = $xml }
    }
    $agent = Read-Profile $AgentSettings $script:AgentProfileName 'agent settings'
    Test-AgentProfile $agent.Xml -NoDeviceID:$NoDeviceID
    $plan = @($agent, (Read-Profile $LoginItems $script:LoginItemsProfileName 'login items'))
    if ($PrivilegesSettings) {
        $privileges = Read-Profile $PrivilegesSettings $script:PrivilegesProfileName 'Privileges settings'
        Test-PrivilegesProfile $privileges.Xml
        $plan += $privileges
    }
    $plan | Select-Object DisplayName, FileName, Bytes
}

# Creates each profile, or updates the one of the same name, and assigns it to the group.
# Every name is looked up before anything is written, so an ambiguous one stops it with
# nothing changed. -WhatIf looks things up and writes nothing. Returns one object per
# profile it wrote.
function Publish-AltiwardProfiles {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Profiles,
        [Parameter(Mandatory)][string]$Group
    )
    $groupId = Resolve-OneGroup $Group
    $existing = @{}
    foreach ($p in $Profiles) { $existing[$p.DisplayName] = Resolve-OneConfiguration $p.DisplayName }
    foreach ($p in $Profiles) {
        $id = $existing[$p.DisplayName]
        $body = New-ConfigurationBody $p.DisplayName $p.Bytes $p.FileName
        if ($id) {
            if (-not $PSCmdlet.ShouldProcess("'$($p.DisplayName)' (already in Intune)", "Update it and assign it to '$Group'")) { continue }
            $null = Invoke-AltiwardGraph 'PATCH' "/deviceManagement/deviceConfigurations/$id" $body
            $action = 'Updated'
        } else {
            if (-not $PSCmdlet.ShouldProcess("'$($p.DisplayName)'", "Create it and assign it to '$Group'")) { continue }
            $id = (Invoke-AltiwardGraph 'POST' '/deviceManagement/deviceConfigurations' $body).id
            $action = 'Created'
        }
        $null = Add-Assignment $id $groupId
        [pscustomobject]@{ Name = $p.DisplayName; Action = $action; Id = $id }
    }
}

Export-ModuleMember -Function Test-AgentProfile, Test-PrivilegesProfile, New-ConfigurationBody,
    Invoke-AltiwardGraph, Resolve-OneGroup, Resolve-OneConfiguration, Add-Assignment,
    Get-AltiwardProfilePlan, Publish-AltiwardProfiles
