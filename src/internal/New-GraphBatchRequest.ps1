function New-GraphBatchRequest {
    <#
    .SYNOPSIS
    Function creates PSObject(s) representing request(s) that can be used in Graph Api batching.

    .DESCRIPTION
    Function creates PSObject(s) representing request(s) that can be used in Graph Api batching.

    PSObject will look like this:
        @{
            Method  = "GET"
            URL     = "/deviceManagement/managedDevices/38027eb9-1f3e-49ea-bf91-f7b7f07c3a63"
            Id      = "deviceInfo"
        }

        Method = method that will be used when sending the request
        URL = ARM api URL that should be requested
        Id = ID that has to be unique across the batch requests

    .PARAMETER method
    Request method.

    Possible values: 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'.

    By default GET.

    .PARAMETER url
    Request URL in relative form like "/deviceManagement/managedDevices/38027eb9-1f3e-49ea-bf91-f7b7f07c3a63" a.k.a. without the "https://graph.microsoft.com/<apiVersion>" prefix (API version is specified when the batch is invoked).

    When the 'placeholder' parameter is specified, for each value it contains, new request url will be generated with such value used instead of the '<placeholder>' string.

    .PARAMETER placeholder
    Array of items (string, integers, ..) that will be used in the request url ('url' parameter) instead of the "<placeholder>" string.

    .PARAMETER header
    Header that should be added to each request in the batch.

    .PARAMETER body
    Body that should be added to each request in the batch.

    .PARAMETER id
    Id of the request.
    If created request will be invoked via 'Invoke-GraphBatchRequest' function, this Id will be saved in the returned object's 'RequestId' property.
    Can only be specified when 'url' parameter contains just one value.
    If url with placeholder is used, suffix "_<randomnumber>" will be added to each generated request id. This way each one is unique and at the same time you are able to filter the request results based on it in case you merge multiple different requests in one final batch.

    Cannot contain "\" character, because Invoke-MgRestMethod used for sending request automatically tries to convert the returned JSON back and it fails because of this special character.

    By default random-generated-number.

    .PARAMETER placeholderAsId
    Switch to use current 'placeholder' value used in the request URL as an request ID.

    BEWARE that request ID has to be unique across the pools of all batch requests, therefore use this switch with a caution!

    .EXAMPLE
    $batchRequest = New-GraphBatchRequest -url "/deviceManagement/managedDevices/38027eb9-1f3e-49ea-bf91-f7b7f07c3a63?`$select=id,devicename&`$expand=DetectedApps", "/deviceManagement/managedDevices/aaa932b4-5af4-4120-86b1-ab64b964a56s?`$select=id,devicename&`$expand=DetectedApps"

    Invoke-GraphBatchRequest -batchRequest $batchRequest -graphVersion beta

    Creates batch request object containing both urls & run it ('DetectedApps' property can be retrieved only when requested devices one by one).

    .EXAMPLE
    $deviceId = (Get-MgBetaDeviceManagementManagedDevice -Property id -All).Id

    New-GraphBatchRequest -url "/deviceManagement/managedDevices/<placeholder>?`$select=id,devicename&`$expand=DetectedApps" -placeholder $deviceId | Invoke-GraphBatchRequest -graphVersion beta

    Creates batch request object containing dynamically generated urls for every id in the $deviceId array & run it ('DetectedApps' property can be retrieved only when requested devices one by one).

    .EXAMPLE
    $devices = Get-MgBetaDeviceManagementManagedDevice -Property Id, AzureAdDeviceId, OperatingSystem -All

    $windowsClient = $devices | ? OperatingSystem -EQ 'Windows'

    $batchRequest = @(
        # get bitlocker keys for all windows devices
        New-GraphBatchRequest -url "/informationProtection/bitlocker/recoveryKeys?`$filter=deviceId eq '<placeholder>'" -id "bitlocker" -placeholder $windowsClient.AzureAdDeviceId

        # get LAPS
        New-GraphBatchRequest -url "/directory/deviceLocalCredentials/<placeholder>?`$select=credentials" -id "laps" -placeholder $windowsClient.AzureAdDeviceId

        # get all users
        New-GraphBatchRequest -url "/users" -id "users"
    )

    $batchResult = Invoke-GraphBatchRequest -batchRequest $batchRequest -graphVersion beta

    $bitlockerKeyList = $batchResult | ? RequestId -like "bitlocker*"
    $lapsKeyList = $batchResult | ? RequestId -like "laps*"
    $userList = $batchResult | ? RequestId -eq "users"

    Merging multiple different batch queries together.

    .EXAMPLE
    $devices = Get-MgBetaDeviceManagementManagedDevice -Property Id, AzureAdDeviceId, OperatingSystem -All

    $macOSClient = $devices | ? OperatingSystem -EQ 'macOS'

    New-GraphBatchRequest -url "/deviceManagement/managedDevices('<placeholder>')/getFileVaultKey" -placeholderAsId -placeholder $macOSClient.Id | Invoke-GraphBatchRequest -graphVersion beta

    Get fileVault keys for all MacOs devices, where returned object's RequestId property will contain Id of the corresponding MacOS device and Value property will contains the key itself.

    .EXAMPLE
    $body = @{
        DisplayName= "test"
        MailEnabled= $false
        securityEnabled= $true
        MailNickName= "test"
        description= "test"
    }

    $header = @{
        "Content-Type"= "application/json"
    }

    New-GraphBatchRequest -method POST -url "/groups/" -body $body -header $header | Invoke-GraphBatchRequest -Verbose

    Create specified group.

    .NOTES
    Author: @AndrewZtrhgf

    HomePage: https://doitpshway.com

    HomeModule: MSGraphStuff

    https://learn.microsoft.com/en-us/graph/json-batching
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [ValidateNotNullOrEmpty()]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')]
        [string] $method = "GET",

        [Parameter(Mandatory = $true)]
        [Alias("urlWithPlaceholder")]
        [string[]] $url,

        $placeholder,

        [hashtable] $header,

        [hashtable] $body,

        [Parameter(ParameterSetName = "Id")]
        [ValidateScript( {
            if ($_ -like "*\*") {
                throw "Id ($_) can't contain '\' character!"
            } else {
                $true
            }
        })]
        [string] $id,

        [Parameter(ParameterSetName = "PlaceholderAsId")]
        [switch] $placeholderAsId
    )

    #region validity checks
    if ($id -and @($url).count -gt 1) {
        throw "'id' parameter cannot be used with multiple urls"
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

    if ($placeholderAsId) {
        $placeholder | % {
            if ($_ -like "*\*") {
                throw "'placeholderAsId' parameter cannot be used when 'placeholder' contains '\' character (value: '$_')!"
            }
        }
    }

    # method is case sensitive!
    $method = $method.ToUpper()
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
        # fix common mistake where there are multiple following slashes
        $_ = $_ -replace "(?<!^https:)/{2,}", "/"

        if ($_ -like "http*" -or $_ -like "*/beta/*" -or $_ -like "*/v1.0/*" -or $_ -like "*/graph.microsoft.com/*") {
            throw "url '$_' has to be in the relative form (without the whole 'https://graph.microsoft.com/<apiversion>' part)!"
        }

        $property = [ordered]@{
            method = $method
            URL    = $_
        }

        if ($id) {
            if ($placeholder -and $placeholder.count -gt 1) {
                $property.id = ($id + "_" + (Get-Random))
            } else {
                $property.id = $id
            }
        } elseif ($placeholderAsId -and $placeholder) {
            $property.id = @($placeholder)[$index]
        } else {
            $property.id = Get-Random
        }

        if ($header) {
            $property.headers = $header
        }

        if ($body) {
            $property.body = $body
        }

        New-Object -TypeName PSObject -Property $property

        ++$index
    }
}