function New-AzureBatchRequest {
    <#
    .SYNOPSIS
    Function creates PSObject(s) representing request(s) that can be used in Azure Resource Manager Api batching.

    .DESCRIPTION
    Function creates PSObject(s) representing request(s) that can be used in Azure Resource Manager Api batching.

    PSObject will look like this:
        @{
            Name       = "mggroupperm"
            HttpMethod = "GET"
            URL        = "https://management.azure.com/providers/Microsoft.Management/managementGroups/SOMEMGGROUP/providers/microsoft.authorization/permissions?api-version=2018-01-01-preview"
        }

        Name = de-facto ID that has to be unique across the batch requests
        HttpMethod = method that will be used when sending the request
        URL = ARM api URL that should be requested

    .PARAMETER method
    Request method.

    By default GET.

    .PARAMETER url
    Request URL in absolute (https://management.azure.com/providers/Microsoft.Management/managementGroups/SOMEMGGROUP/providers/microsoft.authorization/permissions?api-version=2018-01-01-preview) or relative form (/providers/Microsoft.Management/managementGroups/SOMEMGGROUP/providers/microsoft.authorization/permissions?api-version=2018-01-01-preview) a.k.a. without the "https://management.azure.com" prefix.

    When the 'placeholder' parameter is specified, for each value it contains, new request url will be generated with such value used instead of the '<placeholder>' string.

    It needs to contain the api-version parameter, otherwise it will throw an error!
    For example: 'https://management.azure.com/subscriptions/.../roleEligibilitySchedules?api-version=2020-10-01'.
    If you are unsure what api you can use:
     - use the one from the example above and in case the request fails with 400 error, check the error message for the correct api version.
     - use official corresponding Az cmdlet with -debug parameter (Get-AzStorageAccount -debug) and check the 'Absolute uri' output.
     - developer tools (F12) in your browser when using Azure Portal and check the request url there.

    .PARAMETER placeholder
    Array of items (string, integers, ..) that will be used in the request url (defined in 'url' parameter) instead of the "<placeholder>" string.

    .PARAMETER requestHeaderDetails
    RequestHeaderDetails (header) as a hashtable that should be added to each request in the batch.

    "requestHeaderDetails" = @{
        "commandName" = "fx.Microsoft_Azure_AD.ServicesPermissions.getPermissions"
    }

    .PARAMETER content
    Content hashtable that should be added to each request in the batch.

    .PARAMETER name
    Name (Id) of the request.
    Can only be specified only when 'url' parameter contains one value.
    If url with placeholder is used, suffix "_<randomnumber>" will be added to each generated request id. This way each one is unique and at the same time you are able to filter the request results based on it in case you merge multiple different requests in one final batch.

    By default random-generated-number.

    .PARAMETER placeholderAsId
    Switch to use current 'placeholder' value used in the request URL as a request ID.

    BEWARE that request ID has to be unique across the pools of all batch requests, therefore use this switch with a caution!

    .EXAMPLE
    $batchRequest = New-AzureBatchRequest -url "/providers/Microsoft.Authorization/roleDefinitions?%24filter=type%20eq%20%27BuiltInRole%27&api-version=2022-05-01-preview", "/subscriptions/f3b08c7f-99a9-4a70-ba56-1e877abb77f7/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01"

    Invoke-AzureBatchRequest -batchRequest $batchRequest

    Creates batch request object containing both urls & run it.

    .EXAMPLE
    $subscriptionId = (Get-AzSubscription | ? State -EQ 'Enabled').Id

    New-AzureBatchRequest -url "https://management.azure.com/subscriptions/<placeholder>/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01" -placeholder $subscriptionId | Invoke-AzureBatchRequest

    Creates batch request object containing dynamically generated urls for every id in the $subscriptionId array & run it.

    .EXAMPLE
    $subscriptionId = (Get-AzSubscription | ? State -EQ 'Enabled').Id

    $batchRequest = New-AzureBatchRequest -url "https://management.azure.com/subscriptions/<placeholder>/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01" -placeholder $subscriptionId

    # you need to process all requests by chunks of 20 items
    $payload = @{
        requests = $batchRequest[0..19]
    }

    Invoke-AzRestMethod -Uri "https://management.azure.com/batch?api-version=2020-06-01" -Method POST -Payload ($payload | ConvertTo-Json -Depth 20)

    .EXAMPLE
    $arcMachines = Get-ArcMachineOverview

    New-AzureBatchRequest -url "<placeholder>/providers/Microsoft.HybridConnectivity/endpoints/default?api-version=2023-03-15" -placeholder $arcMachines.resourceId -placeholderAsId | Invoke-AzureBatchRequest

    Check connectivity endpoints for all ARC machines, where returned object's Name property will contain the resource ID of the corresponding ARC machine for easy identification of results.

    .EXAMPLE
    $query = @'
        resources
        | where isnotnull(properties.accessPolicies) and array_length(properties.accessPolicies) > 0
        | mv-expand accessPolicy = properties.accessPolicies
        | project
            id,
            resourceName = name,
            resourceType = type,
            resourceGroup,
            subscriptionId,
            accessPolicy
'@

    $content = @{
        query = $query
        subscriptions = @()
        options = @{
            '$top'=1000
            '$skipToken' = "ew0KICAiJGlkIjogIjEiLA0KICAiTWF4Um93cyI6IDEwMDAsDQogICJSb3dzVG9Ta2lwIjogMTAwMCwNCiAgIkt1c3RvQ2x1c3RlclVybCI6ICJodHRwczovL2FyZy1uZXUtMTMtc2YuYXJnLmNvcmUud2luZG93cy5uZXQiDQp9"
        }
    }

    New-AzureBatchRequest -method POST -url "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01" -content $content | Invoke-AzureBatchRequest

    Invoke KQL query against Azure Resource Graph using batch request.

    .NOTES
    Uses undocumented API https://github.com/Azure/azure-sdk-for-python/issues/9271 :).
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'PATCH')]
        [string] $method = "GET",

        [Parameter(Mandatory = $true)]
        [Alias("urlWithPlaceholder")]
        [string[]] $url,

        [Parameter(Mandatory = $true, ParameterSetName = "DynamicUrl")]
        $placeholder,

        [hashtable] $requestHeaderDetails,

        [hashtable] $content,

        [Parameter(ParameterSetName = "Name")]
        [Alias("id")]
        [string] $name,

        [Parameter(ParameterSetName = "DynamicUrl")]
        [switch] $placeholderAsId
    )

    #region validity checks
    if ($name -and @($url).count -gt 1) {
        throw "'name' parameter cannot be used with multiple urls"
    }

    if ($placeholder -and $url -notlike "*<placeholder>*") {
        throw "You have specified 'placeholder' parameter, but 'url' parameter doesn't contain string '<placeholder>' for replace."
    }

    if (!$placeholder -and $url -like "*<placeholder>*") {
        throw "You have specified 'url' with '<placeholder>' in it, but not the 'placeholder' parameter itself."
    }

    if ($placeholderAsId -and !$placeholder) {
        throw "'placeholderAsId' parameter cannot be used without specifying 'placeholder' parameter"
    }

    if ($placeholderAsId -and $placeholder -and @($url).count -gt 1) {
        throw "'placeholderAsId' parameter cannot be used with multiple urls"
    }

    # api version check
    $url | % {
        if ($_ -notlike "*api-version=*") {
            throw "URL '$_' is missing what api to use (api-version=2025-01-01 or similar). For example: 'https://management.azure.com/subscriptions/.../roleEligibilitySchedules?api-version=2020-10-01'. If you are unsure what api you can use, use the one from the example above and in case the request fails with 400 error, check the error message for the correct api version. Or use official Az cmdlet with -debug parameter and check the 'Absolute uri' output."
        }
    }
    #endregion validity checks

    if ($placeholder) {
        $url = $placeholder | % {
            $p = $_

            $url | % {
                $_ -replace "<placeholder>", $p
            }
        }
    }

    $index = 0

    $url | % {
        # fix common mistake where there are multiple slashes
        $_ = $_ -replace "(?<!^https:)/{2,}", "/"

        #region url validity checks
        if ($_ -notlike "https://management.azure.com/*" -and $_ -notlike "/*") {
            throw "url '$_' has to be in the relative (without the 'https://management.azure.com' prefix and starting with the '/') or absolute form!"
        }

        if ($_ -notmatch "/subscriptions/|\?" -and $_ -notmatch "/providers/|\?" -and $_ -notmatch "/resources/|\?" -and $_ -notmatch "/locations/|\?" -and $_ -notmatch "/tenants/|\?" -and $_ -notmatch "/bulkdelete/|\?") {
            throw "url '$_' is not valid. Is should starts with:`n/subscriptions, /providers, /resources, /locations, /tenants or /bulkdelete!"
        }
        #endregion url validity checks

        $property = [ordered]@{
            HttpMethod = $method
            URL        = $_
        }

        if ($name) {
            if ($placeholder -and $placeholder.count -gt 1) {
                $property.Name = ($name + "_" + (Get-Random))
            } else {
                $property.Name = $name
            }
        } elseif ($placeholderAsId -and $placeholder) {
            $property.Name = @($placeholder)[$index]
        } else {
            $property.Name = Get-Random
        }

        if ($requestHeaderDetails) {
            $property.requestHeaderDetails = $requestHeaderDetails
        }

        if ($content) {
            $property.content = $content
        }

        New-Object -TypeName PSObject -Property $property

        ++$index
    }
}