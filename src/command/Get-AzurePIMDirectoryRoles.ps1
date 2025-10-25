function Get-AzurePIMDirectoryRoles {
    param (
        [Parameter(Mandatory = $true)]
        [string] $rootFolder
    )

    #region functions
    function Get-PIMDirectoryRoleEligibleAssignment {
        <#
        .SYNOPSIS
        Function returns Azure Directory role eligible assignments.

        .DESCRIPTION
        Function returns Azure Directory role eligible assignments.

        .PARAMETER skipAssignmentSettings
        If specified, the function will not retrieve assignment settings for the roles. This can speed up the function if you don't need the detailed settings.

        .EXAMPLE
        Get-PIMDirectoryRoleEligibleAssignment
        #>

        [CmdletBinding()]
        param (
            [switch] $skipAssignmentSettings
        )

        if (!(Get-Command Get-MgContext -ErrorAction silentlycontinue) -or !(Get-MgContext)) {
            throw "$($MyInvocation.MyCommand): Authentication needed. Please call Connect-MgGraph."
        }

        Invoke-MgGraphRequest -Uri "v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=roleDefinition,principal" | Get-MgGraphAllPages | % {
            if ($skipAssignmentSettings) {
                $_ | select *, @{n = 'PrincipalName'; e = { $_.principal.displayName } }, @{n = 'RoleName'; e = { $_.roleDefinition.displayName } }
            } else {
                $rules = Get-PIMDirectoryRoleAssignmentSetting -roleId $_.roleDefinitionId -dontBeautify

                $_ | select *, @{n = 'PrincipalName'; e = { $_.principal.displayName } }, @{n = 'RoleName'; e = { $_.roleDefinition.displayName } }, @{n = 'Policy'; e = { $rules } }
            }
        }
    }

    function Get-PIMDirectoryRoleAssignmentSetting {
        <#
        .SYNOPSIS
        Gets PIM assignment settings for a given Azure AD directory role.

        .DESCRIPTION
        This function retrieves Privileged Identity Management (PIM) policy assignment settings for a specified Azure AD directory role, including activation duration, enablement rules, approval requirements, notification settings, and more. You can specify the role by name or ID.

        .PARAMETER roleName
        The display name of the Azure AD directory role to query. Mandatory if using the roleName parameter set.

        .PARAMETER roleId
        The object ID of the Azure AD directory role to query. Mandatory if using the roleId parameter set.

        .EXAMPLE
        Get-PIMDirectoryRoleAssignmentSetting -roleName "Global Administrator"
        Retrieves PIM assignment settings for the Global Administrator role.

        .EXAMPLE
        Get-PIMDirectoryRoleAssignmentSetting -roleId "12345678-aaaa-bbbb-cccc-1234567890ab"
        Retrieves PIM assignment settings for the specified role ID.
        #>

        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, ParameterSetName = "roleName")]
            [string] $roleName,

            [Parameter(Mandatory = $true, ParameterSetName = "roleId")]
            [string] $roleId,

            [switch] $dontBeautify
        )

        if (!(Get-Command Get-MgContext -ErrorAction silentlycontinue) -or !(Get-MgContext)) {
            throw "$($MyInvocation.MyCommand): Authentication needed. Please call Connect-MgGraph."
        }

        if ($roleName) {
            $response = Invoke-MgGraphRequest -Uri "v1.0/roleManagement/directory/roleDefinitions?`$filter=displayname eq '$roleName'" | Get-MgGraphAllPages
            $roleID = $response.Id
            Write-Verbose "roleID = $roleID"
            if (!$roleID) {
                throw "Role $roleName not found. Search is CASE SENSITIVE!"
            }
        }

        # get PIM policyID for that role
        $response = Invoke-MgGraphRequest -Uri "v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeType eq 'DirectoryRole' and roleDefinitionId eq '$roleID' and scopeId eq '/' " | Get-MgGraphAllPages
        $policyID = $response.policyID
        Write-Verbose "policyID = $policyID"

        # get the rules
        $response = Invoke-MgGraphRequest -Uri "v1.0/policies/roleManagementPolicies/$policyID/rules" | Get-MgGraphAllPages

        if ($dontBeautify) {
            [PSCustomObject]@{
                RoleName = $roleName
                RoleID   = $roleID
                PolicyID = $policyID
                Rules    = $response
            }
        } else {
            # Maximum end user activation duration in Hour (PT24H) // Max 24H in portal but can be greater
            $_activationDuration = $($response | Where-Object { $_.id -eq "Expiration_EndUser_Assignment" }).maximumDuration # | Select-Object -ExpandProperty maximumduration
            # End user enablement rule (MultiFactorAuthentication, Justification, Ticketing)
            $_enablementRules = $($response | Where-Object { $_.id -eq "Enablement_EndUser_Assignment" }).enabledRules
            # Active assignment requirement
            $_activeAssignmentRequirement = $($response | Where-Object { $_.id -eq "Enablement_Admin_Assignment" }).enabledRules
            # Authentication context
            $_authenticationContext_Enabled = $($response | Where-Object { $_.id -eq "AuthenticationContext_EndUser_Assignment" }).isEnabled
            $_authenticationContext_value = $($response | Where-Object { $_.id -eq "AuthenticationContext_EndUser_Assignment" }).claimValue

            # approval required
            $_approvalrequired = $($response | Where-Object { $_.id -eq "Approval_EndUser_Assignment" }).setting.isapprovalrequired
            # approvers
            $approvers = $($response | Where-Object { $_.id -eq "Approval_EndUser_Assignment" }).setting.approvalStages.primaryApprovers
            if (( $approvers | Measure-Object | Select-Object -ExpandProperty Count) -gt 0) {
                $approvers | ForEach-Object {
                    if ($_."@odata.type" -eq "#microsoft.graph.groupMembers") {
                        $_.userType = "group"
                        $_.id = $_.groupID
                    } else {
                        #"@odata.type": "#microsoft.graph.singleUser",
                        $_.userType = "user"
                        $_.id = $_.userID
                    }

                    $_approvers += '@{"id"="' + $_.id + '";"description"="' + $_.description + '";"userType"="' + $_.userType + '"},'
                }
            }

            # permanent assignmnent eligibility
            $_eligibilityExpirationRequired = $($response | Where-Object { $_.id -eq "Expiration_Admin_Eligibility" }).isExpirationRequired
            if ($_eligibilityExpirationRequired -eq "true") {
                $_permanentEligibility = "false"
            } else {
                $_permanentEligibility = "true"
            }
            # maximum assignment eligibility duration
            $_maxAssignmentDuration = $($response | Where-Object { $_.id -eq "Expiration_Admin_Eligibility" }).maximumDuration

            # permanent activation
            $_activeExpirationRequired = $($response | Where-Object { $_.id -eq "Expiration_Admin_Assignment" }).isExpirationRequired
            if ($_activeExpirationRequired -eq "true") {
                $_permanentActiveAssignment = "false"
            } else {
                $_permanentActiveAssignment = "true"
            }
            # maximum activation duration
            $_maxActiveAssignmentDuration = $($response | Where-Object { $_.id -eq "Expiration_Admin_Assignment" }).maximumDuration

            # Notification Eligibility Alert (Send notifications when members are assigned as eligible to this role)
            $_Notification_Admin_Admin_Eligibility = $response | Where-Object { $_.id -eq "Notification_Admin_Admin_Eligibility" }
            # Notification Eligibility Assignee (Send notifications when members are assigned as eligible to this role: Notification to the assigned user (assignee))
            $_Notification_Eligibility_Assignee = $response | Where-Object { $_.id -eq "Notification_Requestor_Admin_Eligibility" }
            # Notification Eligibility Approvers (Send notifications when members are assigned as eligible to this role: request to approve a role assignment renewal/extension)
            $_Notification_Eligibility_Approvers = $response | Where-Object { $_.id -eq "Notification_Approver_Admin_Eligibility" }

            # Notification Active Assignment Alert (Send notifications when members are assigned as active to this role)
            $_Notification_Active_Alert = $response | Where-Object { $_.id -eq "Notification_Admin_Admin_Assignment" }
            # Notification Active Assignment Assignee (Send notifications when members are assigned as active to this role: Notification to the assigned user (assignee))
            $_Notification_Active_Assignee = $response | Where-Object { $_.id -eq "Notification_Requestor_Admin_Assignment" }
            # Notification Active Assignment Approvers (Send notifications when members are assigned as active to this role: Request to approve a role assignment renewal/extension)
            $_Notification_Active_Approvers = $response | Where-Object { $_.id -eq "Notification_Approver_Admin_Assignment" }

            # Notification Role Activation Alert (Send notifications when eligible members activate this role: Role activation alert)
            $_Notification_Activation_Alert = $response | Where-Object { $_.id -eq "Notification_Admin_EndUser_Assignment" }
            # Notification Role Activation Assignee (Send notifications when eligible members activate this role: Notification to activated user (requestor))
            $_Notification_Activation_Assignee = $response | Where-Object { $_.id -eq "Notification_Requestor_EndUser_Assignment" }
            # Notification Role Activation Approvers (Send notifications when eligible members activate this role: Request to approve an activation)
            $_Notification_Activation_Approver = $response | Where-Object { $_.id -eq "Notification_Approver_EndUser_Assignment" }


            [PSCustomObject]@{
                RoleName                                                     = $roleName
                RoleID                                                       = $roleID
                PolicyID                                                     = $policyId
                ActivationDuration                                           = $_activationDuration
                EnablementRules                                              = $_enablementRules -join ','
                ActiveAssignmentRequirement                                  = $_activeAssignmentRequirement -join ','
                AuthenticationContext_Enabled                                = $_authenticationContext_Enabled
                AuthenticationContext_Value                                  = $_authenticationContext_value
                ApprovalRequired                                             = $_approvalrequired
                Approvers                                                    = $_approvers -join ','
                AllowPermanentEligibleAssignment                             = $_permanentEligibility
                MaximumEligibleAssignmentDuration                            = $_maxAssignmentDuration
                AllowPermanentActiveAssignment                               = $_permanentActiveAssignment
                MaximumActiveAssignmentDuration                              = $_maxActiveAssignmentDuration
                Notification_Eligibility_Alert_isDefaultRecipientEnabled     = $($_Notification_Admin_Admin_Eligibility.isDefaultRecipientsEnabled)
                Notification_Eligibility_Alert_NotificationLevel             = $($_Notification_Admin_Admin_Eligibility.notificationLevel)
                Notification_Eligibility_Alert_Recipients                    = $($_Notification_Admin_Admin_Eligibility.notificationRecipients) -join ','
                Notification_Eligibility_Assignee_isDefaultRecipientEnabled  = $($_Notification_Eligibility_Assignee.isDefaultRecipientsEnabled)
                Notification_Eligibility_Assignee_NotificationLevel          = $($_Notification_Eligibility_Assignee.NotificationLevel)
                Notification_Eligibility_Assignee_Recipients                 = $($_Notification_Eligibility_Assignee.notificationRecipients) -join ','
                Notification_Eligibility_Approvers_isDefaultRecipientEnabled = $($_Notification_Eligibility_Approvers.isDefaultRecipientsEnabled)
                Notification_Eligibility_Approvers_NotificationLevel         = $($_Notification_Eligibility_Approvers.NotificationLevel)
                Notification_Eligibility_Approvers_Recipients                = $($_Notification_Eligibility_Approvers.notificationRecipients -join ',')
                Notification_Active_Alert_isDefaultRecipientEnabled          = $($_Notification_Active_Alert.isDefaultRecipientsEnabled)
                Notification_Active_Alert_NotificationLevel                  = $($_Notification_Active_Alert.notificationLevel)
                Notification_Active_Alert_Recipients                         = $($_Notification_Active_Alert.notificationRecipients -join ',')
                Notification_Active_Assignee_isDefaultRecipientEnabled       = $($_Notification_Active_Assignee.isDefaultRecipientsEnabled)
                Notification_Active_Assignee_NotificationLevel               = $($_Notification_Active_Assignee.notificationLevel)
                Notification_Active_Assignee_Recipients                      = $($_Notification_Active_Assignee.notificationRecipients -join ',')
                Notification_Active_Approvers_isDefaultRecipientEnabled      = $($_Notification_Active_Approvers.isDefaultRecipientsEnabled)
                Notification_Active_Approvers_NotificationLevel              = $($_Notification_Active_Approvers.notificationLevel)
                Notification_Active_Approvers_Recipients                     = $($_Notification_Active_Approvers.notificationRecipients -join ',')
                Notification_Activation_Alert_isDefaultRecipientEnabled      = $($_Notification_Activation_Alert.isDefaultRecipientsEnabled)
                Notification_Activation_Alert_NotificationLevel              = $($_Notification_Activation_Alert.NotificationLevel)
                Notification_Activation_Alert_Recipients                     = $($_Notification_Activation_Alert.NotificationRecipients -join ',')
                Notification_Activation_Assignee_isDefaultRecipientEnabled   = $($_Notification_Activation_Assignee.isDefaultRecipientsEnabled)
                Notification_Activation_Assignee_NotificationLevel           = $($_Notification_Activation_Assignee.NotificationLevel)
                Notification_Activation_Assignee_Recipients                  = $($_Notification_Activation_Assignee.NotificationRecipients -join ',')
                Notification_Activation_Approver_isDefaultRecipientEnabled   = $($_Notification_Activation_Approver.isDefaultRecipientsEnabled)
                Notification_Activation_Approver_NotificationLevel           = $($_Notification_Activation_Approver.NotificationLevel)
                Notification_Activation_Approver_Recipients                  = $($_Notification_Activation_Approver.NotificationRecipients -join ',')
            }
        }
    }
    #endregion functions

    Get-PIMDirectoryRoleEligibleAssignment | % {
        $item = $_

        $itemId = $item.roleEligibilityScheduleId

        $outputFileName = Join-Path -Path $rootFolder -ChildPath "$itemId.json"

        if ($outputFileName.Length -gt 255 -and (Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -ErrorAction SilentlyContinue) -ne 1) {
            throw "Output file path '$outputFileName' is longer than 255 characters. Enable long path support to continue!"
        }

        $item | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
    }
}