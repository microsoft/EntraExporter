function Get-AzurePIMResources {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $rootFolder
    )

    if (!(Get-Command 'Get-AzAccessToken' -ErrorAction silentlycontinue) -or !($azAccessToken = Get-AzAccessToken -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) -or $azAccessToken.ExpiresOn -lt [datetime]::now) {
        throw "$($MyInvocation.MyCommand): Authentication needed. Please call Connect-AzAccount."
    }

    #region functions
    function Expand-ObjectProperty {
        <#
        .SYNOPSIS
        Function integrates selected object property into the main object a.k.a flattens the main object.

        .DESCRIPTION
        Function integrates selected object property into the main object a.k.a flattens the main object.

        Moreover if the integrated property contain '@odata.type' child property, ObjectType

        .PARAMETER inputObject
        Object(s) with that should be flattened.

        .PARAMETER propertyName
        Name opf the object property you want to integrate into the main object.
        Beware that any same-named existing properties in the main object will be overwritten!

        .PARAMETER addObjectType
        (make sense only for MS Graph related objects)
        Switch to add extra 'ObjectType' property in case there is '@odata.type' property in the integrated object that contains type of the object (for example 'user instead of '#microsoft.graph.user' etc).

        .EXAMPLE
        $managementGroupNameList = (Get-AzManagementGroup).Name
        New-AzureBatchRequest -url "https://management.azure.com/providers/Microsoft.Management/managementGroups/<placeholder>/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01" -placeholder $managementGroupNameList | Invoke-AzureBatchRequest | Expand-ObjectProperty -propertyName Properties

        .EXAMPLE
        Get-MgDirectoryObjectById -ids 34568a12-8861-45ff-afef-9282cd9871c6 | Expand-ObjectProperty -propertyName AdditionalProperties -addObjectType
        #>

        [CmdletBinding()]
        param(
            [parameter(ValueFromPipeline)]
            [object[]] $inputObject,

            [Parameter(Mandatory = $true)]
            [string] $propertyName,

            [switch] $addObjectType
        )

        process {
            foreach ($object in $inputObject) {
                if ($object.$propertyName) {
                    $propertyType = $object.$propertyName.gettype().name

                    if ($propertyType -eq 'PSCustomObject') {
                        ($object.$propertyName | Get-Member -MemberType NoteProperty).Name | % {
                            $pName = $_
                            $pValue = $object.$propertyName.$pName

                            Write-Verbose "Adding property '$pName' to the pipeline object"
                            $object | Add-Member -MemberType NoteProperty -Name $pName -Value $pValue -Force
                        }
                    } elseif ($propertyType -in 'Dictionary`2', 'Hashtable') {
                        $object.$propertyName.GetEnumerator() | % {
                            $pName = $_.key
                            $pValue = $_.value

                            $object | Add-Member -MemberType NoteProperty -Name $pName -Value $pValue -Force

                            if ($addObjectType -and $pName -eq "@odata.type") {
                                Write-Verbose "Adding extra property 'ObjectType' to the pipeline object"
                                $object | Add-Member -MemberType NoteProperty -Name 'ObjectType' -Value ($pValue -replace [regex]::Escape("#microsoft.graph.")) -Force
                            }
                        }
                    } else {
                        throw "Undefined property type '$propertyType'"
                    }

                    $object | Select-Object -Property * -ExcludeProperty $propertyName
                } else {
                    Write-Warning "There is no '$propertyName' property"
                    $object
                }
            }
        }
    }

    function Get-PIMResourceRoleAssignmentSetting {
        <#
        .SYNOPSIS
        Gets PIM assignment settings for a given Azure resource role at a specific scope.

        .DESCRIPTION
        This function retrieves Privileged Identity Management (PIM) policy assignment settings for a specified Azure resource role (such as Reader, Contributor, etc.) at a given scope (subscription, resource group, or resource). You can specify the role by name or ID.

        .PARAMETER rolename
        The name of the Azure resource role to query. Mandatory if using the rolename parameter set.

        .PARAMETER roleId
        The object ID of the Azure resource role to query. Mandatory if using the roleId parameter set.

        .PARAMETER scope
        The Azure scope (subscription, resource group, or resource) to query for the role assignment settings. Mandatory.

        .EXAMPLE
        Get-PIMResourceRoleAssignmentSetting -rolename "Reader" -scope "/subscriptions/xxxx/resourceGroups/yyyy"
        Retrieves PIM assignment settings for the Reader role at the specified resource group scope.

        .EXAMPLE
        Get-PIMResourceRoleAssignmentSetting -roleId "acdd72a7-3385-48ef-bd42-f606fba81ae7" -scope "/subscriptions/xxxx/resourceGroups/yyyy"
        Retrieves PIM assignment settings for the specified role ID at the given scope.
        #>

        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, ParameterSetName = "rolename")]
            [string] $rolename,
            [Parameter(Mandatory = $true, ParameterSetName = "roleId")]
            [string] $roleId,
            [Parameter(Mandatory = $true)]
            [string] $scope
        )

        $scope = $scope.TrimStart('/')

        if (!(Get-Command 'Get-AzAccessToken' -ErrorAction silentlycontinue) -or !($azAccessToken = Get-AzAccessToken -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) -or $azAccessToken.ExpiresOn -lt [datetime]::now) {
            throw "$($MyInvocation.MyCommand): Authentication needed. Please call Connect-AzAccount."
        }

        $base = "https://management.azure.com"
        $endpoint = "$base/$scope/providers/Microsoft.Authorization"
        # Get ID of the role $rolename assignable at the provided scope
        if ($rolename) {
            $restUri = "$endpoint/roleDefinitions?api-version=2022-04-01&`$filter=roleName eq '$rolename'"
            $roleID = ((Invoke-AzRestMethod -Uri $restUri -ErrorAction Stop).content | ConvertFrom-Json).id
        } else {
            $roleID = "/$scope/providers/Microsoft.Authorization/roleDefinitions/$roleId"
        }
        # get the role assignment for the roleID
        $restUri = "$endpoint/roleManagementPolicyAssignments?api-version=2020-10-01&`$filter=roleDefinitionId eq '$roleID'"
        $policyId = ((Invoke-AzRestMethod -Uri $restUri -ErrorAction Stop).content | ConvertFrom-Json).value.properties.policyId
        # get the role policy for the policyID
        $restUri = "$base/$policyId/?api-version=2020-10-01"
        ((Invoke-AzRestMethod -Uri $restUri -ErrorAction Stop).content | ConvertFrom-Json).properties
    }

    function Get-PIMManagementGroupEligibleAssignment {
        <#
        .SYNOPSIS
        Function returns all PIM eligible IAM assignments on selected (all) Azure Management group(s).

        .DESCRIPTION
        Function returns all PIM eligible IAM assignments on selected (all) Azure Management group(s).

        .PARAMETER name
        Name of the Azure Management Group(s) to process.

        .PARAMETER skipAssignmentSettings
        If specified, the function will not retrieve assignment settings for the roles. This can speed up the function if you don't need the detailed settings.

        .EXAMPLE
        Get-PIMManagementGroupEligibleAssignment

        Returns all PIM eligible IAM assignments over all Azure Management Groups.

        .EXAMPLE
        Get-PIMManagementGroupEligibleAssignment -Name IT_test

        Returns all PIM eligible IAM assignments over selected Azure Management Group.

        .NOTES
        Requires "Management Group Reader" role assigned at "Tenant Root Group" level to be able to read Management Groups!
        #>

        [CmdletBinding()]
        param (
            [string[]] $name,

            [switch] $skipAssignmentSettings
        )

        if (!(Get-Command 'Get-AzAccessToken' -ErrorAction silentlycontinue) -or !($azAccessToken = Get-AzAccessToken -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) -or $azAccessToken.ExpiresOn -lt [datetime]::now) {
            throw "$($MyInvocation.MyCommand): Authentication needed. Please call Connect-AzAccount."
        }

        if ($name) {
            $managementGroupNameList = $name
        } else {
            $managementGroupNameList = (Search-AzGraph2 -query "ResourceContainers| where type =~ 'microsoft.management/managementGroups'").Name
        }

        if (!$managementGroupNameList) {
            Write-Warning "No management groups found! Make sure you are granted 'Management Group Reader' role at 'Tenant Root Group' level!"
            return
        }

        New-AzureBatchRequest -url "https://management.azure.com/providers/Microsoft.Management/managementGroups/<placeholder>/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01&`$filter=atScope()" -placeholder $managementGroupNameList | Invoke-AzureBatchRequest | Expand-ObjectProperty -propertyName Properties | Expand-ObjectProperty -propertyName ExpandedProperties | ? memberType -EQ 'Direct' | % {
            if ($skipAssignmentSettings) {
                $assignmentSetting = $null
            } else {
                $roleId = ($_.roleDefinitionId -split "/")[-1]
                $assignmentSetting = Get-PIMResourceRoleAssignmentSetting -roleId $roleId -scope $_.Scope.Id
            }

            $_ | select *, @{n = 'Policy'; e = { $assignmentSetting } }
        }
    }
    
    function Get-PIMSubscriptionEligibleAssignment {
        <#
        .SYNOPSIS
        Retrieves eligible role assignments for selected Azure subscriptions and their resources using PIM.

        .DESCRIPTION
        This function finds all Privileged Identity Management (PIM) eligible role assignments for the specified Azure subscriptions and their resources. If no subscription IDs are provided, it processes all enabled subscriptions in the tenant. The output includes principal, role, scope, and assignment details for each eligible assignment found.

        .PARAMETER id
        One or more Azure subscription IDs to process. If not provided, all enabled subscriptions will be processed automatically.

        .EXAMPLE
        Get-PIMSubscriptionEligibleAssignment
        Retrieves PIM eligible assignments for all enabled subscriptions and their resources.

        .EXAMPLE
        Get-PIMSubscriptionEligibleAssignment -id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        Retrieves PIM eligible assignments for the specified subscription and its resources.

        #>

        [CmdletBinding()]
        param (
            [string[]] $id,

            [switch] $skipAssignmentSettings
        )

        if (!(Get-Command 'Get-AzAccessToken' -ErrorAction silentlycontinue) -or !($azAccessToken = Get-AzAccessToken -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) -or $azAccessToken.ExpiresOn -lt [datetime]::now) {
            throw "$($MyInvocation.MyCommand): Authentication needed. Please call Connect-AzAccount."
        }

        if ($id) {
            $subscriptionId = $id
        } else {
            $subscriptionId = New-AzureBatchRequest -url "/subscriptions?api-version=2018-02-01" | Invoke-AzureBatchRequest | ? { $_.State -eq 'Enabled' } | select -ExpandProperty SubscriptionId
        }

        if (!$subscriptionId) {
            Write-Warning "No subscriptions found!"
            return
        }

        New-AzureBatchRequest -url "/subscriptions/<placeholder>/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01" -placeholder $subscriptionId | Invoke-AzureBatchRequest | Expand-ObjectProperty -propertyName Properties | Expand-ObjectProperty -propertyName ExpandedProperties | ? {$_.memberType -EQ 'Direct' -and $_.Scope.Type -ne "managementgroup" } | % {
            if ($skipAssignmentSettings) {
                $assignmentSetting = $null
            } else {
                $roleId = ($_.roleDefinitionId -split "/")[-1]
                $assignmentSetting = Get-PIMResourceRoleAssignmentSetting -roleId $roleId -scope $_.Scope.Id
            }

            $_ | select *, @{n = 'Policy'; e = { $assignmentSetting } }
        }
    }
    #endregion functions

    $joinChar = "&"

    Get-PIMManagementGroupEligibleAssignment | % {
        $item = $_

        $itemId = $item.roleEligibilityScheduleRequestId -replace "/", $joinChar

        $outputFileName = Join-Path -Path (Join-Path -Path $rootFolder -ChildPath "ManagementGroups") -ChildPath "$itemId.json"

        if ($outputFileName.Length -gt 255 -and (Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -ErrorAction SilentlyContinue) -ne 1) {
            throw "Output file path '$outputFileName' is longer than 255 characters. Enable long path support to continue!"
        }

        $item | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
    }

    Get-PIMSubscriptionEligibleAssignment | ? { $_ } | % {
        $item = $_

        $itemId = $item.roleEligibilityScheduleRequestId -replace "/", $joinChar

        $outputFileName = Join-Path -Path (Join-Path -Path $rootFolder -ChildPath "Subscriptions") -ChildPath "$itemId.json"

        if ($outputFileName.Length -gt 255 -and (Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -ErrorAction SilentlyContinue) -ne 1) {
            throw "Output file path '$outputFileName' is longer than 255 characters. Enable long path support to continue!"
        }

        $item | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
    }
}