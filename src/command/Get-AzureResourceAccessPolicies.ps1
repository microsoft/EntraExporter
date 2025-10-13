function Get-AzureResourceAccessPolicies {
    param (
        [Parameter(Mandatory = $true)]
        [string] $rootFolder
    )

    function Get-AzureResourceAccessPolicy {
        <#
        .SYNOPSIS
        Function returns all Access Policies (not RBAC/IAM) for all Azure resources.

        .DESCRIPTION
        Function returns all Access Policies (not RBAC/IAM) for all Azure resources.
        Access Policies are the custom permission assignment not using Azure RBAC used in KeyVault, etc.

        .PARAMETER expandPermission
        Switch to expand Access Policies permissions one per an assignee.

        .EXAMPLE
        Get-AzureResourceAccessPolicy

        Get all Access Policies (not RBAC/IAM) for all Azure resources.
        #>

        [CmdletBinding()]
        param ()

        $query = @'
    resources
    | where isnotnull(properties.accessPolicies) and array_length(properties.accessPolicies) > 0
    | project
        id,
        resourceName = name,
        resourceType = type,
        location,
        resourceGroup,
        subscriptionId,
        properties,
        tags
'@

        Write-Verbose $query

        Search-AzGraph2 -query $query
    }

    $joinChar = "&"

    Get-AzureResourceAccessPolicy | % {
        $result = $_
        $scopeId = $result.subscriptionId
        $id = $result.id -replace "/", $joinChar

        $outputPath = Join-Path -Path (Join-Path -Path $rootFolder -ChildPath "Subscriptions") -ChildPath $scopeId

        $outputFileName = Join-Path -Path $outputPath -ChildPath "$id.json"

        $result | select * -ExcludeProperty Id | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
    }
}