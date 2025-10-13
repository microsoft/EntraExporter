function Get-AzureResourceIAMData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $rootFolder
    )

    $assignmentsFolder = Join-Path -Path $rootFolder -ChildPath "RoleAssignments"
    $definitionsFolder = Join-Path -Path $rootFolder -ChildPath "RoleDefinitions"

    #region IAM Role assignments export
    #region helper functions
    function _scopeType {
        param ([string] $scope)

        if ($scope -match "^/$") {
            return 'root'
        } elseif ($scope -match "^/subscriptions/[^/]+$") {
            return 'subscription'
        } elseif ($scope -match "^/subscriptions/[^/]+/resourceGroups/[^/]+$") {
            return "resourceGroup"
        } elseif ($scope -match "^/subscriptions/[^/]+/resourceGroups/[^/]+/.+$") {
            return 'resource'
        } elseif ($scope -match "^/providers/Microsoft.Management/managementGroups/.+") {
            return 'managementGroup'
        } else {
            throw 'undefined type'
        }
    }
    #endregion helper functions

    #region build the query
    $query = @'
authorizationresources
| where type == "microsoft.authorization/roleassignments"
| extend scope = tostring(properties['scope'])
| extend principalType = tostring(properties['principalType'])
| extend principalId = tostring(properties['principalId'])
| extend roleDefinitionId = tolower(tostring(properties['roleDefinitionId']))
| extend managementGroupId = iif(
        properties['scope'] startswith "/providers/Microsoft.Management/managementGroups",
        tostring(split(properties['scope'], "/")[-1]),""
    )
| mv-expand createdOn = parse_json(properties).createdOn
| mv-expand updatedOn = parse_json(properties).updatedOn
| join kind=inner (
    authorizationresources
    | where type =~ 'microsoft.authorization/roledefinitions'
    | extend id = tolower(id)
    | project id, properties
) on $left.roleDefinitionId == $right.id
| mv-expand roleDefinitionName = parse_json(properties1).roleName
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project-rename subscriptionName = name
    | project subscriptionId, subscriptionName
) on $left.subscriptionId == $right.subscriptionId
'@

    # define the query output
    $property = "createdOn", "updatedOn", "principalId", "principalType", "scope", "roleDefinitionName", "roleDefinitionId", "managementGroupId", "subscriptionId", "subscriptionName", "resourceGroup"
    $query += "`n| project $($property -join ',')"
    #endregion build the query

    #region run the query
    $kqlResult = Search-AzGraph2 -query $query

    # there can be duplicates with different createdOn/updatedOn, keep just the latest one
    $kqlResult = $kqlResult | Group-Object -Property ($property | ? {$_ -notin "createdOn", "updatedOn"}) | % {if ($_.count -eq 1) {$_.group} else {$_.group | sort updatedOn | select -First 1}}

    if (!$kqlResult) { return }
    #endregion run the query

    # get the principal name from its id
    $idToNameList = Get-AzureDirectoryObject -id ($kqlResult.principalId | select -Unique)

    $joinChar = "&"

    # output the final results
    $kqlResult | select @{n = 'PrincipalName'; e = { $id = $_.PrincipalId; $result = $idToNameList | ? Id -EQ $id; if ($result.DisplayName) { $result.DisplayName } else { $result.mailNickname } } }, PrincipalId, PrincipalType, RoleDefinitionName, RoleDefinitionId, Scope, @{ n = 'ScopeType'; e = { _scopeType $_.scope } }, ManagementGroupId, SubscriptionId, SubscriptionName, ResourceGroup, CreatedOn, UpdatedOn | % {
        $item = $_

        switch ($item.scopeType) {
            'root' {
                $outputPath = Join-Path -Path $assignmentsFolder -ChildPath "Root"
            }
            'managementGroup' {
                $outputPath = Join-Path -Path (Join-Path -Path $assignmentsFolder -ChildPath "ManagementGroups") -ChildPath $item.ManagementGroupId
            }
            'subscription' {
                $outputPath = Join-Path -Path (Join-Path -Path $assignmentsFolder -ChildPath "Subscriptions") -ChildPath $item.SubscriptionId
            }
            'resourceGroup' {
                $outputPath = Join-Path -Path (Join-Path -Path (Join-Path -Path $assignmentsFolder -ChildPath "Subscriptions") -ChildPath $item.SubscriptionId) -ChildPath $item.ResourceGroup
            }
            'resource' {
                # $folder = ($item.Scope.Split("/")[-3..-1] -join $joinChar)
                $folder = $item.Scope -replace "/", $joinChar
                $outputPath = Join-Path -Path (Join-Path -Path (Join-Path -Path (Join-Path -Path $assignmentsFolder -ChildPath "Subscriptions") -ChildPath $item.SubscriptionId) -ChildPath $item.ResourceGroup) -ChildPath $folder
            }
            default {
                throw "Undefined scope type $($item.scopeType)"
            }
        }

        $itemId = $item.principalId + $joinChar + ($item.roleDefinitionId).split("/")[-1]

        $outputFileName = Join-Path -Path $outputPath -ChildPath "$itemId.json"

        if ($outputFileName.Length -gt 255 -and (Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -ErrorAction SilentlyContinue) -ne 1) {
            throw "Output file path '$outputFileName' is longer than 255 characters. Enable long path support to continue!"
        }

        if (Test-Path $outputFileName -ErrorAction SilentlyContinue) {
            # this shouldn't happen!
            Write-Error "File $outputFileName already exists!"
            $outputFileName = $outputFileName + ".replace"
        }

        $item | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
    }
    #endregion IAM Role assignments export

    #region IAM Role definitions export
    #region export built-in RBAC (IAM) roles
    New-AzureBatchRequest -url "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?%24filter=type%20eq%20%27BuiltInRole%27&api-version=2022-05-01-preview" | Invoke-AzureBatchRequest | % {
        $result = $_
        $roleId = $result.name
        $outputPath = Join-Path -Path $definitionsFolder -ChildPath "BuiltInRole"
        $outputFileName = Join-Path -Path $outputPath -ChildPath "$roleId.json"
        $result | select * -ExcludeProperty RequestName | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
    }
    #endregion export built-in RBAC (IAM) roles

    #region export custom RBAC (IAM) roles
    # custom roles are defined on subscription or management group level, so I need to get all subscriptions and management groups first
    # get all subscriptions and management groups
    $scopeList = Search-AzGraph2 -query "
ResourceContainers
| where type =~ 'microsoft.resources/subscriptions' or type =~ 'microsoft.management/managementgroups'
| project name, type, id
"

    # get all custom roles for each subscription and management group
    New-AzureBatchRequest -url "https://management.azure.com/<placeholder>/providers/Microsoft.Authorization/roleDefinitions?%24filter=type%20eq%20%27CustomRole%27&api-version=2022-05-01-preview" -placeholder $scopeList.id -placeholderAsId | Invoke-AzureBatchRequest | % {
        $result = $_
        $scopeId = ($result.RequestName).split("/")[-1]
        $roleId = $result.name

        if ($result.RequestName -like "/providers/Microsoft.Management/managementGroups/*") {
            $outputPath = Join-Path -Path (Join-Path -Path $definitionsFolder -ChildPath "CustomRole\ManagementGroups") -ChildPath $scopeId
        } elseif ($result.RequestName -like "/subscriptions/*") {
            $outputPath = Join-Path -Path (Join-Path -Path $definitionsFolder -ChildPath "CustomRole\Subscriptions") -ChildPath $scopeId
        } else {
            throw "Undefined scope type in $($result.RequestName)"
        }

        $outputFileName = Join-Path -Path $outputPath -ChildPath "$roleId.json"

        $result | select * -ExcludeProperty RequestName | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
    }
    #endregion export custom RBAC (IAM) roles
    #endregion IAM Role definitions export
}