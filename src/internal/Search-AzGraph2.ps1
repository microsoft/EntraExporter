function Search-AzGraph2 {
    <#
    .SYNOPSIS
    Function similar to Search-AzGraph, but with pagination support.

    .DESCRIPTION
    Function similar to Search-AzGraph, but with pagination support.

    .PARAMETER query
    KQL query to run against Azure Resource Manager.

    .PARAMETER scopedSearch
    If specified, the function will search only across the current subscription.

    By default, the function searches across all subscriptions in the tenant.

    .EXAMPLE
    Search-AzGraph2 -query 'resources
    | where type =~ "microsoft.keyvault/vaults"
    | extend accessPolicies = properties.accessPolicies
    | where isnotnull(accessPolicies) and array_length(accessPolicies) > 0
    | project name, resourceGroup, subscriptionId, accessPolicies'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $query,

        [switch] $scopedSearch
    )

    $content = @{
        query = $query
        subscriptions = @()
        options = @{
            '$top'=1000
            resultFormat = "objectArray"
        }
    }

    if ($scopedSearch) {
        $currentSubscription = (Get-AzContext).Subscription
        Write-Verbose "Searching only across current subscription '$($currentSubscription.Name)' ($($currentSubscription.Id))"
        $content.subscriptions = $currentSubscription.Id
    } else {
        Write-Verbose "Searching across all subscriptions in the tenant"
    }

    New-AzureBatchRequest -method POST -url "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01" -content $content | Invoke-AzureBatchRequest
}