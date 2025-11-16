function Invoke-GraphBatchRequest {
    <#
    .SYNOPSIS
    Function to invoke Graph Api batch request(s).

    .DESCRIPTION
    Function to invoke Graph Api batch request(s).

    Handles pagination, throttling and server-side errors.

    .PARAMETER batchRequest
    PSobject(s) representing the requests to be run in a batch.

    Can be created manually or via New-GraphBatchRequest.

    https://learn.microsoft.com/en-us/graph/json-batching?tabs=http#creating-a-batch-request

    .PARAMETER graphVersion
    What api version should be requested.

    Possible values: 'v1.0', 'beta'.

    By default 'v1.0'.

    .PARAMETER dontBeautifyResult
    Switch for returning original/non-modified batch request(s) results.

    By default batch-request-related properties like batch status, headers, nextlink, etc are stripped and the result is converted to PSCustomObject.

    To be able to filter returned objects by their originated request, new property 'RequestId' is added (unless 'dontAddRequestId' switch is used).

    Use if you are not getting the correct results a.k.a. internal function logic may be faulty + create issue ticket so I can fix it :)

    .PARAMETER dontAddRequestId
    Switch to avoid adding extra 'RequestId' property to the "beautified" results.

    .PARAMETER dontFollowNextLink
    Switch to avoid following nextLink urls in case of paginated results.
    By default nextLink urls are followed and all results are returned.
    Useful if you are only interested in the first page of results or using top filter to limit the number of returned objects (even if you use top, nextlink will be present if there are more results available!).

    .PARAMETER separateErrors
    Switch to return batch request errors one by one instead of all at once.

    .EXAMPLE
    [System.Collections.Generic.List[object]] $batchRequest = @()

    $batchRequest.Add((New-GraphBatchRequest -Url "applications" -id "app"))
    $batchRequest.Add((New-GraphBatchRequest -Url "servicePrincipals" -id "sp"))
    $batchRequest.Add((New-GraphBatchRequest -Url "users" -id "user"))
    $batchRequest.Add((New-GraphBatchRequest -Url "groups" -id "group"))

    $allResults = Invoke-GraphBatchRequest -batchRequest $batchRequest

    $servicePrincipalList = $allResults | ? RequestId -eq "sp"
    $applicationList = $allResults | ? RequestId -eq "app"
    $userList = $allResults | ? RequestId -eq "user"
    $groupList = $allResults | ? RequestId -eq "group"

    Creates batch request object (using New-GraphBatchRequest) for getting all Azure applications, Service Principals, Users and Groups & run it.
    The result will be beautified so you get the all results in one array, where each object is enhanced by RequestId property to easily identify the source request.

    .EXAMPLE
    $batchRequest = @((New-GraphBatchRequest -Url "applications" -id "app"), (New-GraphBatchRequest -Url "servicePrincipals" -id "sp"))

    Invoke-GraphBatchRequest -batchRequest $batchRequest -dontBeautifyResult

    Creates batch request object for getting all Azure applications and Service Principals & run it.
    You won't get directly the results, but batch objects instead, where results are stored in body.value (or just body) property.

    .EXAMPLE
    $batchRequest = @(
        [PSCustomObject]@{
            id     = "app"
            method = "GET"
            URL    = "applications"
        },
        [PSCustomObject]@{
            id     = "sp"
            method = "GET"
            URL    = "servicePrincipals"
        }
    )

    $allResults = Invoke-GraphBatchRequest -batchRequest $batchRequest

    $servicePrincipalList = $allResults | ? RequestId -eq "sp"
    $applicationList = $allResults | ? RequestId -eq "app"

    Creates batch request object (without using New-GraphBatchRequest) for getting all Azure applications and Service Principals & run it.
    The result will be beautified so you get the all results in one array, where each object is enhanced by RequestId property to easily identify the source request.

    .EXAMPLE
    $batchRequest = New-GraphBatchRequest -url "/deviceManagement/managedDevices/38027eb9-1f3e-49ea-bf91-f7b7f07c3a63?`$select=id,devicename&`$expand=DetectedApps", "/deviceManagement/managedDevices/aaa932b4-5af4-4120-86b1-ab64b964a56s?`$select=id,devicename&`$expand=DetectedApps"

    Invoke-GraphBatchRequest -batchRequest $batchRequest -graphVersion beta

    Creates batch request object containing both urls & run it.

    .EXAMPLE
    $deviceId = (Get-MgBetaDeviceManagementManagedDevice -Property id -All).Id

    New-GraphBatchRequest -url "/deviceManagement/managedDevices/<placeholder>?`$select=id,devicename&`$expand=DetectedApps" -placeholder $deviceId | Invoke-GraphBatchRequest -graphVersion beta

    Creates batch request object containing dynamically generated urls for every id in the $deviceId array & run it.

    .EXAMPLE
    New-GraphBatchRequest -url "auditLogs/signIns?`$top=1&`$filter=(ServicePrincipalId eq '1be6405d-592d-42dc-9c02-cce874143254') and (signInEventTypes/any(t: t eq 'managedIdentity'))" | Invoke-GraphBatchRequest -graphVersion beta -dontFollowNextLink

    Get just the newest sign-in log entry for the given service principal id (managed identity).
    The result is paginated, but since we are interested just in the newest entry, we don't need to follow the nextLink url.

    .EXAMPLE
    $deviceId = 'ef1a3624-1fae-4961-b9a2-079db366d1ea', '526c2aff-c5e0-49e5-a1fa-36fbf1c3c414'

    New-GraphBatchRequest -url "/deviceManagement/managedDevices/<placeholder>" -placeholder $deviceId | Invoke-GraphBatchRequest -separateErrors -ErrorAction SilentlyContinue -ErrorVariable requestErrors

    $requestErrors | % {
        if ($_.Exception.Source -eq "BatchRequest") {
            # batch request errors

            if ($_.TargetObject.response.status -in 404) {
                Write-Verbose "Ignoring request with id '$($_.TargetObject.request.id)' ($($_.TargetObject.request.url)) as it returned status code $($_.TargetObject.response.status)"
            } else {
                throw $_
            }
        } else {
            # other non-batch-related errors

            throw $_
        }
    }

    Invoke batch request & run it & process errors.

    .NOTES
    Author: @AndrewZtrhgf

    HomePage: https://doitpshway.com

    HomeModule: MSGraphStuff

    https://learn.microsoft.com/en-us/graph/json-batching

    Returned errors contain 'TargetObject' property with original request and response objects for easier troubleshooting.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject[]]$batchRequest,

        [ValidateSet('v1.0', 'beta')]
        [string] $graphVersion = "v1.0",

        [switch] $dontBeautifyResult,

        [switch] $dontAddRequestId,

        [switch] $dontFollowNextLink,

        [switch] $separateErrors
    )

    begin {
        if ($PSCmdlet.MyInvocation.PipelineLength -eq 1) {
            Write-Verbose "Total number of requests to process is $($batchRequest.count)"
        }

        if ($dontBeautifyResult -and $dontAddRequestId) {
            Write-Verbose "'dontAddRequestId' parameter will be ignored, 'RequestId' property is not being added when 'dontBeautifyResult' parameter is used"
        }

        # api batch requests are limited to 20 requests
        $chunkSize = 20
        # base graph api uri
        $uri = "https://graph.microsoft.com"
        # batch uri
        $requestUri = "$uri/$graphVersion/`$batch"
        # buffer to hold chunks of requests
        $requestChunk = [System.Collections.Generic.List[Object]]::new()
        # paginated or remotely failed requests that should be processed too, to get all the results
        $extraRequestChunk = [System.Collections.Generic.List[Object]]::new()
        # throttled requests that have to be repeated after given time
        $throttledRequestChunk = [System.Collections.Generic.List[Object]]::new()

        function _processChunk {
            <#
                .SYNOPSIS
                Helper function with the main chunk-processing logic that invokes batch request.

                Based on request return code and availability of nextlink url it:
                 - creates another request to get missing data
                 - retry the request (with wait time in case of throttled request)
            #>

            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [System.Collections.ArrayList] $requestChunk
            )

            function Is-JSON {
                # to avoid errors when trying to convert non-json strings using ConvertFrom-Json
                # such errors would be captured to ErrorVariable and would interfere with the error handling logic

                [CmdletBinding()]
                param (
                    [string] $InputString
                )

                if ([string]::IsNullOrWhiteSpace($InputString)) {
                    return $false
                }

                switch -Regex ($InputString.TrimStart()) {
                    '^"'    { return "String" }
                    '^{'    { return "Object" }
                    '^\['    { return "Array" }
                    '^true|^false' { return "Boolean" }
                    '^null' { return "Null" }
                    '^-?\d' { return "Number" }
                    default { return $false }
                }
            }

            $duplicityId = $requestChunk.id | Group-Object | ? { $_.Count -gt 1 }
            if ($duplicityId) {
                throw "Batch requests must have unique ids. Id(s): '$(($duplicityId.Name | select -Unique) -join ', ')' is there more than once"
            }

            Write-Debug ($requestChunk | ConvertTo-Json -Depth 10)

            Write-Verbose "Processing batch of $($requestChunk.count) request(s):`n$(($requestChunk | Sort-Object Url | % {" - $($_.Id) - $($_.Url)"} ) -join "`n")"

            #region process given chunk of batch requests
            $start = Get-Date

            $body = @{
                requests = [array]$requestChunk
            }

            $body = $body | ConvertTo-Json -Depth 50

            Write-Verbose $body

            Invoke-MgRestMethod -Method Post -Uri $requestUri -Body $body -ContentType "application/json" -OutputType PSObject | % {
                $responses = $_.responses

                #region return the output
                if ($dontBeautifyResult) {
                    # return original response

                    $responses
                } else {
                    # return just actually requested data without batch-related properties and enhance the returned object with 'RequestId' property for easier filtering

                    foreach ($response in $responses) {
                        $value, $noteProperty = $null
                        if ($response.body) { $noteProperty = $response.body | Get-Member -MemberType NoteProperty }

                        # there was some error, no real values were returned, skipping
                        if ($response.Status -in (400..509)) {
                            continue
                        }

                        if ($response.body.value) {
                            # the result is stored in 'value' property
                            $value = $response.body.value
                        } elseif ($response.body -and $noteProperty.Name -contains '@odata.context' -and $noteProperty.Name -contains 'value') {
                            # the result is stored in 'value' property, but no results were returned, skipping
                            continue
                        } elseif ($response.body) {
                            # the result is in the 'body' property itself
                            $value = $response.body
                        } else {
                            # no results in 'body.value' nor 'body' property itself
                            continue
                        }

                        # return processed output
                        $primitiveTypeList = 'String', 'Int32', 'Int64', 'Boolean', 'Float', 'Double', 'Decimal', 'Char'

                        if ($value.gettype().name -in $primitiveTypeList -or $value[0].gettype().name -in $primitiveTypeList) {
                            # it is a primitive (or list of primitives)

                            if ($dontAddRequestId) {
                                $value
                            } else {
                                [PSCustomObject]@{
                                    Value     = $value
                                    RequestId = $response.Id
                                }
                            }
                        } else {
                            # it is a complex object (hashtable, ..)

                            # properties to return
                            $property = @("*")
                            if (!$dontAddRequestId) {
                                $property += @{n = 'RequestId'; e = { $response.Id } }
                            }

                            $value | select -Property $property -ExcludeProperty '@odata.context', '@odata.nextLink'
                        }
                    }
                }
                #endregion return the output

                #region handle the responses based on their status code
                # load the next pages, retry throttled requests, repeat failed requests, ...

                $failedBatchJob = [System.Collections.Generic.List[Object]]::new()

                foreach ($response in $responses) {
                    # https://learn.microsoft.com/en-us/graph/errors#http-status-codes
                    if ($response.Status -in 200, 201, 204) {
                        # success

                        if ($response.body.'@odata.nextLink') {
                            # paginated (get remaining results by query returned NextLink URL)

                            if ($dontFollowNextLink) {
                                Write-Verbose "Batch result for request '$($response.Id)' is paginated. But 'dontFollowNextLink' switch is set, hence nextLink will not be followed"

                                continue
                            } else {
                                Write-Verbose "Batch result for request '$($response.Id)' is paginated. Nextlink will be processed in the next batch"
                            }

                            $relativeNextLink = $response.body.'@odata.nextLink' -replace [regex]::Escape("https://graph.microsoft.com/$graphVersion/")
                            # make a request object copy, so I can modify it without interfering with the original object
                            $nextLinkRequest = $requestChunk | ? Id -EQ $response.Id | ConvertTo-Json -Depth 10 | ConvertFrom-Json
                            # replace original URL with the nextLink
                            $nextLinkRequest.URL = $relativeNextLink
                            # add the request for later processing
                            $extraRequestChunk.Add($nextLinkRequest)
                        }
                    } elseif ($response.Status -in 429, 509) {
                        # throttled (will be repeated after given time)

                        $jobRetryAfter = $response.Headers.'Retry-After'
                        $throttledBatchRequest = $requestChunk | ? Id -EQ $response.Id

                        Write-Verbose "Batch request with Id: '$($throttledBatchRequest.Id)', Url:'$($throttledBatchRequest.Url)' was throttled, hence will be repeated after $jobRetryAfter seconds"

                        if ($jobRetryAfter -eq 0) {
                            # request can be repeated without any delay
                            #TIP for performance reasons adding to $extraRequestChunk batch (to avoid invocation of unnecessary batch job)
                            $extraRequestChunk.Add($throttledBatchRequest)
                        } else {
                            # request can be repeated after delay
                            # add the request for later processing
                            $throttledRequestChunk.Add($throttledBatchRequest)
                        }

                        # get highest retry-after wait time
                        if ($jobRetryAfter -gt $script:retryAfter) {
                            Write-Verbose "Setting $jobRetryAfter retry-after time"
                            $script:retryAfter = $jobRetryAfter
                        }
                    } elseif ($response.Status -in 500, 502, 503, 504) {
                        # some internal error on remote side (will be repeated)

                        $problematicBatchRequest = $requestChunk | ? Id -EQ $response.Id

                        Write-Verbose "Batch request with Id: '$($problematicBatchRequest.Id)', Url:'$($problematicBatchRequest.Url)' had internal error '$($response.body.error.message)', Code: $($response.Status), hence will be repeated"

                        $extraRequestChunk.Add($problematicBatchRequest)
                    } else {
                        # failed

                        $failedBatchRequest = $requestChunk | ? Id -EQ $response.Id

                        $innerErrorText = $null
                        if ($response.body.error.innerError.code) {
                            $innerErrorText = " (" + $response.body.error.innerError.code + ")"
                        }

                        $errorText = $null
                        if ($response.body.error.message) {
                            # sometimes the error message is not a plain string, but a JSON
                            if (Is-JSON -InputString $response.body.error.message) {
                                $errorText = $response.body.error.message | ConvertFrom-Json -ErrorAction Stop

                                if ($errorText.Error.Message) {
                                    $errorText = $errorText.Error.Message + "($($response.body.error.code))"
                                } elseif ($errorText.Message) {
                                    $errorText = $errorText.Message + " ($($response.body.error.code))"
                                } else {
                                    $errorText = $response.body.error.code
                                }
                            } else {
                                # not a JSON, just a string
                                $errorText = $response.body.error.message
                            }
                        } elseif ($response.body.error.code) {
                                $errorText = $response.body.error.code
                        } else {
                            # no error message, just the status code
                        }

                        $failedBatchJob.Add(
                            @{
                                Id         = $response.Id
                                Url        = $failedBatchRequest.Url
                                StatusCode = $response.Status
                                Error      = "$($errorText)$innerErrorText"
                                Object     = [ordered]@{
                                    request  = $failedBatchRequest
                                    response = $response
                                }
                            }
                        )
                    }
                }

                # return error if critical failure occurred
                if ($failedBatchJob) {
                    if ($separateErrors) {
                        # output errors one by one, so you can handle them separately if needed
                        $failedBatchJob | % {
                            #TIP only the first one will be returned if $ErrorActionPreference is set to stop!
                            $errorMsg = "`nFailed batch request:`n$(" - Id: '$($_.Id)'", " - Url: '$($_.Url)'", " - StatusCode: '$($_.StatusCode)'", " - Error: '$($_.Error)'`n`n" -join "`n")"
                            $exception = New-Object System.InvalidOperationException $errorMsg
                            $exception.Source = "BatchRequest"

                            Write-Error -ErrorRecord (New-Object System.Management.Automation.ErrorRecord($exception, $null, "InvalidOperation", $_.Object))
                        }
                    } else {
                        #TIP all errors at once, because batch can contain non-related requests and if errorAction is set to stop, only the first error would be returned, which can be confusing
                        $errorMsg = "`nFollowing batch request(s) failed:`n`n$(($failedBatchJob | % { " - Id: '$($_.Id)'", " - Url: '$($_.Url)'", " - StatusCode: '$($_.StatusCode)'", " - Error: '$($_.Error)'" -join "`n" }) -join "`n`n")"
                        $exception = New-Object System.InvalidOperationException $errorMsg
                        $exception.Source = "BatchRequest"

                        Write-Error -ErrorRecord (New-Object System.Management.Automation.ErrorRecord($exception, $null, "InvalidOperation", $failedBatchJob.Object))
                    }
                }
                #endregion handle the responses based on their status code
            }

            $end = Get-Date

            Write-Verbose "It took $((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds to process the batch"
            #endregion process given chunk of batch requests
        }
    }

    process {
        # check url validity
        $batchRequest.URL | % {
            if ($_ -like "http*" -or $_ -like "*/beta/*" -or $_ -like "*/v1.0/*" -or $_ -like "*/graph.microsoft.com/*") {
                throw "url '$_' has to be relative (without the whole 'https://graph.microsoft.com/<apiversion>' part)!"
            }
        }

        foreach ($request in $batchRequest) {
            $requestChunk.Add($request)

            # check if the buffer has reached the required chunk size
            if ($requestChunk.count -eq $chunkSize) {
                [int] $script:retryAfter = 0
                _processChunk $requestChunk

                # clear the buffer
                $requestChunk.Clear()

                # process requests that need to be repeated (paginated, failed on remote server,...)
                if ($extraRequestChunk) {
                    Write-Warning "Processing $($extraRequestChunk.count) paginated or server-side-failed request(s)"

                    $PSBoundParameters['batchRequest'] = $extraRequestChunk
                    Invoke-GraphBatchRequest @PSBoundParameters

                    $extraRequestChunk.Clear()
                }

                # process throttled requests
                if ($throttledRequestChunk) {
                    Write-Warning "Processing $($throttledRequestChunk.count) throttled request(s) with $script:retryAfter seconds wait time"

                    Start-Sleep -Seconds $script:retryAfter

                    $PSBoundParameters['batchRequest'] = $throttledRequestChunk
                    Invoke-GraphBatchRequest @PSBoundParameters

                    $throttledRequestChunk.Clear()
                }
            }
        }
    }

    end {
        # process any remaining requests in the buffer

        if ($requestChunk.Count -gt 0) {
            [int] $script:retryAfter = 0
            _processChunk $requestChunk

            # process requests that need to be repeated (paginated, failed on remote server,...)
            if ($extraRequestChunk) {
                Write-Warning "Processing $($extraRequestChunk.count) paginated or server-side-failed request(s)"
                $PSBoundParameters['batchRequest'] = $extraRequestChunk
                Invoke-GraphBatchRequest @PSBoundParameters
            }

            # process throttled requests
            if ($throttledRequestChunk) {
                Write-Warning "Processing $($throttledRequestChunk.count) throttled request(s) with $script:retryAfter seconds wait time"

                Start-Sleep -Seconds $script:retryAfter

                $PSBoundParameters['batchRequest'] = $throttledRequestChunk
                Invoke-GraphBatchRequest @PSBoundParameters
            }
        }
    }
}