function Get-AzureResourceAccessPolicies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $rootFolder
    )

    if (!(Get-Command 'Get-AzAccessToken' -ErrorAction silentlycontinue) -or !($azAccessToken = Get-AzAccessToken -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) -or $azAccessToken.ExpiresOn -lt [datetime]::now) {
        Write-Warning "Skipping Get-AzureResourceAccessPolicies. Not connected to Azure."
        return
    }

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

        .NOTES
        Requires Reader role on Tenant Root Group to be able to read all subscriptions and their resources!
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

    $joinChar = [System.IO.Path]::DirectorySeparatorChar

    Get-AzureResourceAccessPolicy | % {
        $result = $_
        $id = $result.id
        $id = $id -replace "/subscriptions/", ""
        $id = $id -replace "/", $joinChar

        $outputFileName = Join-Path -Path $rootFolder -ChildPath "$id.json"

        $result | SaveAs-SortedJSON -Path $outputFileName
    }
}