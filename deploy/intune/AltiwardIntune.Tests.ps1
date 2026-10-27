# Pester 5 tests for AltiwardIntune.psm1. They import the module only, never the script,
# and never sign in: Invoke-AltiwardGraph is mocked, so no request reaches Microsoft.
#   pwsh -c 'Invoke-Pester deploy/intune -CI'

BeforeAll {
    Import-Module "$PSScriptRoot/AltiwardIntune.psm1" -Force

    $script:MdmDir = Join-Path $PSScriptRoot '../mdm'

    # The shipped agent profile, as text, with ServerURL and EnrollmentToken edited.
    function script:Get-EditedAgentText {
        (Get-Content -Raw (Join-Path $script:MdmDir 'com.altiward.agent.mobileconfig')).
            Replace('https://api.altiward.example', 'https://altiward.contoso.example').
            Replace('REPLACE_WITH_TENANT_AGENT_TOKEN', 'contoso=0123456789abcdef')
    }

    # A pinned copy of the Privileges profile, as the agent release ships it.
    function script:Get-PinnedPrivilegesText {
        (Get-Content -Raw (Join-Path $script:MdmDir 'corp.sap.privileges.mobileconfig')).
            Replace('REPLACE_WITH_SHA256_OF_SIGNED_HOOK', ('ab' * 32))
    }

    # Writes the three profiles into $TestDrive and returns their paths.
    function script:New-Files {
        $files = @{
            Agent      = Join-Path $TestDrive 'com.altiward.agent.mobileconfig'
            Privileges = Join-Path $TestDrive 'corp.sap.privileges.mobileconfig'
            LoginItems = Join-Path $TestDrive 'altiward-login-items.mobileconfig'
        }
        [IO.File]::WriteAllText($files.Agent, (script:Get-EditedAgentText))
        [IO.File]::WriteAllText($files.Privileges, (script:Get-PinnedPrivilegesText))
        Copy-Item (Join-Path $script:MdmDir 'altiward-login-items.mobileconfig') $files.LoginItems
        $files
    }

    # A pretend Graph. Tests set $global:GraphState and read $global:GraphCalls.
    $script:FakeGraph = {
        $p = [uri]::UnescapeDataString($Path)
        $global:GraphCalls += [pscustomobject]@{ Method = $Method; Path = $p; Body = $Body }
        $s = $global:GraphState
        $name = if ($p -match "displayName eq '(.*)'") { $Matches[1].Replace("''", "'") }
        if ($p -match '^/groups\?') {
            return @{ value = @($s.Groups | Where-Object { $_.displayName -eq $name }) }
        }
        if ($p -match '^/deviceManagement/deviceConfigurations\?') {
            return @{ value = @($s.Configurations | Where-Object { $_.displayName -eq $name }) }
        }
        if ($p -match '^/deviceManagement/deviceConfigurations/([^/]+)/assignments$') {
            $existing = $s.Assignments[$Matches[1]]
            return @{ value = @(if ($existing) { $existing }) }
        }
        if ($Method -eq 'POST' -and $p -eq '/deviceManagement/deviceConfigurations') {
            return @{ id = 'new-' + $Body.displayName }
        }
        return @{}
    }

    function script:Use-FakeGraph($State) {
        $global:GraphCalls = @()
        $global:GraphState = $State
        Mock Invoke-AltiwardGraph -ModuleName AltiwardIntune -MockWith $script:FakeGraph
    }

    function script:Get-Writes { @($global:GraphCalls | Where-Object { $_.Method -ne 'GET' }) }
}

AfterAll {
    Remove-Variable GraphCalls, GraphState -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Test-AgentProfile' {
    It 'passes the shipped file once ServerURL and EnrollmentToken are changed' {
        { Test-AgentProfile ([xml](script:Get-EditedAgentText)) } | Should -Not -Throw
    }

    It 'throws on the unedited file' {
        $x = [xml](Get-Content -Raw (Join-Path $script:MdmDir 'com.altiward.agent.mobileconfig'))
        { Test-AgentProfile $x } | Should -Throw '*Still the example value*'
    }

    It 'names the key that is still an example' {
        $text = (script:Get-EditedAgentText).Replace('contoso=0123456789abcdef', 'REPLACE_WITH_TENANT_AGENT_TOKEN')
        { Test-AgentProfile ([xml]$text) } | Should -Throw '*EnrollmentToken*Still the example value*'
        $text = (script:Get-EditedAgentText).Replace('https://altiward.contoso.example', 'https://api.altiward.example')
        { Test-AgentProfile ([xml]$text) } | Should -Throw '*ServerURL*Still the example value*'
    }

    It 'throws when MDMDeviceID is missing' {
        $text = (script:Get-EditedAgentText).Replace('<key>MDMDeviceID</key>', '<key>Other</key>')
        { Test-AgentProfile ([xml]$text) } | Should -Throw '*MDMDeviceID must be {{deviceid}}*'
    }

    It 'throws on {{DeviceID}}, which Intune does not fill in' {
        $text = (script:Get-EditedAgentText).Replace('{{deviceid}}', '{{DeviceID}}')
        { Test-AgentProfile ([xml]$text) } | Should -Throw '*MDMDeviceID must be {{deviceid}}*'
    }

    It 'lets -NoDeviceID skip the MDMDeviceID check' {
        $text = (script:Get-EditedAgentText).Replace('{{deviceid}}', 'something-else')
        { Test-AgentProfile ([xml]$text) -NoDeviceID } | Should -Not -Throw
    }
}

Describe 'Test-PrivilegesProfile' {
    It 'throws on the placeholder checksum' {
        $x = [xml](Get-Content -Raw (Join-Path $script:MdmDir 'corp.sap.privileges.mobileconfig'))
        { Test-PrivilegesProfile $x } | Should -Throw '*use the file from the agent release*'
    }

    It 'passes a pinned copy' {
        { Test-PrivilegesProfile ([xml](script:Get-PinnedPrivilegesText)) } | Should -Not -Throw
    }
}

Describe 'New-ConfigurationBody' {
    It 'makes a macOS custom configuration carrying the file as base64' {
        $bytes = [byte[]](0, 1, 2, 250, 255)
        $b = New-ConfigurationBody 'Altiward: agent settings' $bytes 'com.altiward.agent.mobileconfig'
        $b['@odata.type'] | Should -Be '#microsoft.graph.macOSCustomConfiguration'
        $b.displayName | Should -Be 'Altiward: agent settings'
        $b.payloadName | Should -Be 'Altiward: agent settings'
        $b.payloadFileName | Should -Be 'com.altiward.agent.mobileconfig'
        $b.payload | Should -Be ([Convert]::ToBase64String($bytes))
        $b.deploymentChannel | Should -Be 'deviceChannel'
    }
}

Describe 'Resolve-OneGroup and Resolve-OneConfiguration' {
    It 'finds one group' {
        script:Use-FakeGraph @{ Groups = @(@{ id = 'g1'; displayName = 'Pilot Macs' }) }
        Resolve-OneGroup 'Pilot Macs' | Should -Be 'g1'
    }

    It 'throws when no group has the name' {
        script:Use-FakeGraph @{ Groups = @() }
        { Resolve-OneGroup 'Pilot Macs' } | Should -Throw "*No group named 'Pilot Macs'*"
    }

    It 'throws when two groups share the name' {
        script:Use-FakeGraph @{ Groups = @(@{ id = 'g1'; displayName = 'Pilot' }, @{ id = 'g2'; displayName = 'Pilot' }) }
        { Resolve-OneGroup 'Pilot' } | Should -Throw '*More than one group named*'
    }

    It 'doubles a quote in the name, as the filter needs' {
        script:Use-FakeGraph @{ Groups = @(@{ id = 'g1'; displayName = "Phil's Macs" }) }
        Resolve-OneGroup "Phil's Macs" | Should -Be 'g1'
        $global:GraphCalls[0].Path | Should -BeLike "*displayName eq 'Phil''s Macs'*"
    }

    It 'finds one profile, or none' {
        script:Use-FakeGraph @{ Configurations = @(@{ id = 'c1'; displayName = 'Altiward: agent settings' }) }
        Resolve-OneConfiguration 'Altiward: agent settings' | Should -Be 'c1'
        Resolve-OneConfiguration 'Altiward: login items' | Should -BeNullOrEmpty
    }

    It 'throws when two profiles share the name' {
        script:Use-FakeGraph @{ Configurations = @(
                @{ id = 'c1'; displayName = 'Altiward: agent settings' },
                @{ id = 'c2'; displayName = 'Altiward: agent settings' }) }
        { Resolve-OneConfiguration 'Altiward: agent settings' } | Should -Throw '*More than one configuration profile named*'
    }
}

Describe 'Add-Assignment' {
    It 'keeps an existing exclusion and adds the group' {
        script:Use-FakeGraph @{ Assignments = @{ c1 = @(
                    @{ id = 'a1'; target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'excluded' } },
                    @{ id = 'a2'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'other' } }) } }
        Add-Assignment 'c1' 'pilot'
        $post = script:Get-Writes
        $post.Count | Should -Be 1
        $post[0].Method | Should -Be 'POST'
        $post[0].Path | Should -Be '/deviceManagement/deviceConfigurations/c1/assign'
        $targets = @($post[0].Body.assignments | ForEach-Object { "$($_.target['@odata.type'])|$($_.target.groupId)" })
        $targets | Should -Be @(
            '#microsoft.graph.exclusionGroupAssignmentTarget|excluded',
            '#microsoft.graph.groupAssignmentTarget|other',
            '#microsoft.graph.groupAssignmentTarget|pilot')
    }

    It 'sends nothing when the group is already assigned' {
        script:Use-FakeGraph @{ Assignments = @{ c1 = @(
                    @{ id = 'a1'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'pilot' } }) } }
        Add-Assignment 'c1' 'pilot'
        script:Get-Writes | Should -BeNullOrEmpty
    }

    It 'assigns a profile that has no assignments yet' {
        script:Use-FakeGraph @{ Assignments = @{} }
        Add-Assignment 'c1' 'pilot'
        $post = script:Get-Writes
        @($post[0].Body.assignments).Count | Should -Be 1
        $post[0].Body.assignments[0].target.groupId | Should -Be 'pilot'
    }
}

Describe 'Publish-AltiwardProfiles' {
    BeforeEach {
        $script:f = script:New-Files
    }

    It 'creates the profiles that do not exist, and assigns each to the group' {
        script:Use-FakeGraph @{ Groups = @(@{ id = 'pilot'; displayName = 'Pilot Macs' }); Configurations = @(); Assignments = @{} }
        $plan = Get-AltiwardProfilePlan -AgentSettings $script:f.Agent -LoginItems $script:f.LoginItems
        Publish-AltiwardProfiles -Profiles $plan -Group 'Pilot Macs'
        $w = script:Get-Writes
        @($w | Where-Object { $_.Path -eq '/deviceManagement/deviceConfigurations' -and $_.Method -eq 'POST' }).Count | Should -Be 2
        @($w | Where-Object { $_.Path -like '*/assign' }).Count | Should -Be 2
        ($w | Where-Object { $_.Path -eq '/deviceManagement/deviceConfigurations' }).Body.displayName |
            Should -Be @('Altiward: agent settings', 'Altiward: login items')
    }

    It 'PATCHes an existing agent profile instead of creating a second' {
        script:Use-FakeGraph @{
            Groups         = @(@{ id = 'pilot'; displayName = 'Pilot Macs' })
            Configurations = @(@{ id = 'c-agent'; displayName = 'Altiward: agent settings' })
            Assignments    = @{}
        }
        $plan = Get-AltiwardProfilePlan -AgentSettings $script:f.Agent -LoginItems $script:f.LoginItems
        Publish-AltiwardProfiles -Profiles $plan -Group 'Pilot Macs'
        $w = script:Get-Writes
        $patch = @($w | Where-Object { $_.Method -eq 'PATCH' })
        $patch.Count | Should -Be 1
        $patch[0].Path | Should -Be '/deviceManagement/deviceConfigurations/c-agent'
        @($w | Where-Object { $_.Method -eq 'POST' -and $_.Body.displayName -eq 'Altiward: agent settings' }).Count | Should -Be 0
    }

    It 'sends the file exactly as given' {
        script:Use-FakeGraph @{ Groups = @(@{ id = 'pilot'; displayName = 'Pilot Macs' }); Configurations = @(); Assignments = @{} }
        $plan = Get-AltiwardProfilePlan -AgentSettings $script:f.Agent -LoginItems $script:f.LoginItems
        Publish-AltiwardProfiles -Profiles $plan -Group 'Pilot Macs'
        $sent = ((script:Get-Writes) | Where-Object { $_.Body.displayName -eq 'Altiward: agent settings' }).Body
        $sent.payload | Should -Be ([Convert]::ToBase64String([IO.File]::ReadAllBytes($script:f.Agent)))
        $sent.payloadFileName | Should -Be 'com.altiward.agent.mobileconfig'
    }

    It 'sends the Privileges profile only with -PrivilegesSettings' {
        script:Use-FakeGraph @{ Groups = @(@{ id = 'pilot'; displayName = 'Pilot Macs' }); Configurations = @(); Assignments = @{} }
        $without = Get-AltiwardProfilePlan -AgentSettings $script:f.Agent -LoginItems $script:f.LoginItems
        $without.DisplayName | Should -Not -Contain 'Altiward: settings for SAP Privileges'
        $with = Get-AltiwardProfilePlan -AgentSettings $script:f.Agent -LoginItems $script:f.LoginItems -PrivilegesSettings $script:f.Privileges
        $with.DisplayName | Should -Contain 'Altiward: settings for SAP Privileges'
        Publish-AltiwardProfiles -Profiles $with -Group 'Pilot Macs'
        @((script:Get-Writes) | Where-Object { $_.Body.displayName -eq 'Altiward: settings for SAP Privileges' }).Count | Should -Be 1
    }

    It 'refuses an ambiguous group before writing anything' {
        script:Use-FakeGraph @{ Groups = @(@{ id = 'g1'; displayName = 'Pilot' }, @{ id = 'g2'; displayName = 'Pilot' }) }
        $plan = Get-AltiwardProfilePlan -AgentSettings $script:f.Agent -LoginItems $script:f.LoginItems
        { Publish-AltiwardProfiles -Profiles $plan -Group 'Pilot' } | Should -Throw '*More than one group named*'
        script:Get-Writes | Should -BeNullOrEmpty
    }

    It 'refuses an ambiguous profile name before writing anything' {
        script:Use-FakeGraph @{
            Groups         = @(@{ id = 'pilot'; displayName = 'Pilot Macs' })
            Configurations = @(@{ id = 'c1'; displayName = 'Altiward: login items' }, @{ id = 'c2'; displayName = 'Altiward: login items' })
        }
        $plan = Get-AltiwardProfilePlan -AgentSettings $script:f.Agent -LoginItems $script:f.LoginItems
        { Publish-AltiwardProfiles -Profiles $plan -Group 'Pilot Macs' } | Should -Throw '*More than one configuration profile named*'
        script:Get-Writes | Should -BeNullOrEmpty
    }

    It 'writes nothing under -WhatIf' {
        script:Use-FakeGraph @{
            Groups         = @(@{ id = 'pilot'; displayName = 'Pilot Macs' })
            Configurations = @(@{ id = 'c-agent'; displayName = 'Altiward: agent settings' })
            Assignments    = @{}
        }
        $plan = Get-AltiwardProfilePlan -AgentSettings $script:f.Agent -LoginItems $script:f.LoginItems
        Publish-AltiwardProfiles -Profiles $plan -Group 'Pilot Macs' -WhatIf
        script:Get-Writes | Should -BeNullOrEmpty
    }
}

Describe 'Get-AltiwardProfilePlan' {
    BeforeEach { $script:f = script:New-Files }

    It 'refuses an unedited agent profile before any request' {
        $unedited = Join-Path $TestDrive 'unedited.mobileconfig'
        Copy-Item (Join-Path $script:MdmDir 'com.altiward.agent.mobileconfig') $unedited
        { Get-AltiwardProfilePlan -AgentSettings $unedited -LoginItems $script:f.LoginItems } | Should -Throw '*Still the example value*'
    }

    It 'refuses a Privileges profile whose checksum is a placeholder' {
        $raw = Join-Path $TestDrive 'raw.mobileconfig'
        Copy-Item (Join-Path $script:MdmDir 'corp.sap.privileges.mobileconfig') $raw
        { Get-AltiwardProfilePlan -AgentSettings $script:f.Agent -LoginItems $script:f.LoginItems -PrivilegesSettings $raw } |
            Should -Throw '*use the file from the agent release*'
    }

    It 'says which file is missing' {
        { Get-AltiwardProfilePlan -AgentSettings (Join-Path $TestDrive 'nope.mobileconfig') -LoginItems $script:f.LoginItems } |
            Should -Throw '*nope.mobileconfig*'
    }
}
