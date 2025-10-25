function Get-AzurePIMGroups {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $rootFolder
    )

    #region functions
    function Get-PIMSupportedGroup {
        <#
        .SYNOPSIS
        Get all groups that can be theoretically used for PIM assignment.

        Unfortunately I don't know a better way to filter out groups that have eligible PIM assignments.
        #>

        [CmdletBinding()]
        param()

        if (!(Get-Command Get-MgContext -ErrorAction silentlycontinue) -or !(Get-MgContext)) {
            throw "$($MyInvocation.MyCommand): Authentication needed. Please call Connect-MgGraph."
        }

        Invoke-MgGraphRequest -Uri "v1.0/groups?`$select=Id,DisplayName,OnPremisesSyncEnabled,GroupTypes,MailEnabled,SecurityEnabled" | Get-MgGraphAllPages | ? { $_.onPremisesSyncEnabled -eq $null -and $_.GroupTypes -notcontains 'DynamicMembership' -and !($_.MailEnabled -and $_.SecurityEnabled -and $_.GroupTypes -notcontains 'Unified') -and !($_.MailEnabled -and !$_.SecurityEnabled) }
    }

    function Get-PIMGroupEligibleAssignment {
        <#
        .SYNOPSIS
        Returns eligible assignments for Azure AD groups (PIM).

        .DESCRIPTION
        This function finds Azure AD groups that have Privileged Identity Management (PIM) eligible assignments. It can process specific group IDs or search all groups for PIM eligibility. Optionally, it retrieves assignment settings for each group and translates object IDs to display names for easier interpretation.

        .PARAMETER groupId
        One or more Azure AD group IDs to process. If not specified, all possible PIM-enabled groups will be searched.

        .PARAMETER skipAssignmentSettings
        If specified, the function will not retrieve assignment settings for the roles. This can speed up the function if you don't need the detailed settings.

        .EXAMPLE
        Get-PIMGroupEligibleAssignment
        Returns all Azure AD groups with PIM eligible assignments and their assignment settings.

        .EXAMPLE
        Get-PIMGroupEligibleAssignment -groupId "12345678-aaaa-bbbb-cccc-1234567890ab" -skipAssignmentSettings
        Returns PIM eligible assignments for the specified group, skipping assignment settings for faster results.

        .NOTES
        Author: @AndrewZtrhgf
        #>

        [CmdletBinding()]
        param (
            [string[]] $groupId,

            [switch] $skipAssignmentSettings
        )

        if (!(Get-Command Get-MgContext -ErrorAction silentlycontinue) -or !(Get-MgContext)) {
            throw "$($MyInvocation.MyCommand): Authentication needed. Please call Connect-MgGraph."
        }

        if ($groupId) {
            $possiblePIMGroupId = $groupId
        } else {
            # I don't know how to get the list of PIM enabled groups so I have to find them
            # by searching for eligible role assignments for every PIM-supported-type group
            Write-Warning "Searching for groups with PIM eligible assignment. This can take a while."

            $possiblePIMGroupId = (Get-PIMSupportedGroup).id
        }

        if (!$possiblePIMGroupId) { return }

        # search for groups that have some PIM settings defined
        $groupWithPIMEligibleAssignment = New-GraphBatchRequest -url "identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '<placeholder>'" -placeholder $possiblePIMGroupId | Invoke-GraphBatchRequest -graphVersion v1.0 -dontAddRequestId

        if (!$groupWithPIMEligibleAssignment) {
            Write-Warning "None of the groups have PIM eligible assignments"
            return
        }

        #region get assignment settings for all PIM groups
        if (!$skipAssignmentSettings) {
            $assignmentSettingBatch = [System.Collections.Generic.List[Object]]::new()
            $groupWithPIMEligibleAssignment | % {
                $groupId = $_.groupId
                $type = $_.accessId

                # https://learn.microsoft.com/en-us/graph/api/policyroot-list-rolemanagementpolicyassignments?view=graph-rest-beta&tabs=http#for-pim-for-groups
                $assignmentSettingBatch.Add((New-GraphBatchRequest -url "policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$groupId' and scopeType eq 'Group' and roleDefinitionId eq '$type'&`$expand=policy(`$expand=rules)"))
            }

            $assignmentSettingList = Invoke-GraphBatchRequest -batchRequest $assignmentSettingBatch -graphVersion beta -dontAddRequestId
        }
        #endregion get assignment settings for all PIM groups

        #region translate all Ids to corresponding DisplayName
        $idToTranslate = [System.Collections.Generic.List[Object]]::new()
        $groupWithPIMEligibleAssignment.PrincipalId | % { $idToTranslate.add($_) }
        $groupWithPIMEligibleAssignment.groupId | % { $idToTranslate.add($_) }
        $idToTranslate = $idToTranslate | select -Unique
        $translationList = Get-AzureDirectoryObject -id $idToTranslate
        #endregion translate all Ids to corresponding DisplayName

        # output the results
        $groupWithPIMEligibleAssignment | % {
            $groupId = $_.groupId
            $type = $_.accessId
            $principalId = $_.PrincipalId

            # get the PIM assignment settings
            if ($skipAssignmentSettings) {
                $assignmentSetting = $null
            } else {
                $assignmentSetting = $assignmentSettingList | ? { $_.ScopeId -eq $groupId -and $_.roleDefinitionId -eq $type }
            }

            $_ | select Id, CreatedDateTime, ModifiedDateTime, Status, GroupId, @{n = 'GroupName'; e = { ($translationList | ? Id -EQ $groupId).DisplayName } }, PrincipalId, @{n = 'PrincipalName'; e = { ($translationList | ? Id -EQ $principalId).DisplayName } }, AccessId, MemberType, ScheduleInfo, @{ n = 'Policy'; e = { $assignmentSetting.policy } }
        }
    }
    #endregion functions

    Get-PIMGroupEligibleAssignment | % {
        $item = $_

        $itemId = $item.id

        $outputFileName = Join-Path -Path $rootFolder -ChildPath "$itemId.json"

        if ($outputFileName.Length -gt 255 -and (Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -ErrorAction SilentlyContinue) -ne 1) {
            throw "Output file path '$outputFileName' is longer than 255 characters. Enable long path support to continue!"
        }

        $item | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
    }
}