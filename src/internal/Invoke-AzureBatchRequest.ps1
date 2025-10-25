function Invoke-AzureBatchRequest {
    <#
    .SYNOPSIS
    Function to invoke Azure Resource Manager Api batch request(s).

    .DESCRIPTION
    Function to invoke Azure Resource Manager Api batch request(s).

    Handles throttling and server-side errors.

    .PARAMETER batchRequest
    PSobject(s) representing the requests to be run in a batch.

    Can be created manually or via New-AzureBatchRequest.

    https://github.com/Azure/azure-sdk-for-python/issues/9271

    .PARAMETER dontBeautifyResult
    Switch for returning original/non-modified batch request(s) results.

    By default batch-request-related properties like batch status, headers, nextlink, etc are stripped.

    To be able to filter returned objects by their originated request, new property 'RequestName' is added.

    .PARAMETER dontAddRequestName
    Switch to avoid adding extra 'RequestName' property to the "beautified" results.

    .PARAMETER separateErrors
    Switch to return batch request errors one by one instead of all at once.
    Moreover returned errors will contain 'TargetObject' property with original request and response objects for easier troubleshooting.

    .EXAMPLE
    $batch = (
        @{
            Name       = "group"
            HttpMethod = "GET"
            URL        = "https://management.azure.com/providers/Microsoft.Management/managementGroups/SOMEMGGROUP/providers/microsoft.authorization/permissions?api-version=2018-01-01-preview"
        },

        @{
            Name       = "subPim"
            HttpMethod = "GET"
            URL        = "/subscriptions/f3b08c7f-99a9-4a70-ba56-1e877abb77f7/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01"
        }
    )

    Invoke-AzureBatchRequest -batchRequest $batch

    Invokes both requests in one batch.

    .EXAMPLE
    $batchRequest = New-AzureBatchRequest -url "/providers/Microsoft.Authorization/roleDefinitions?%24filter=type%20eq%20%27BuiltInRole%27&api-version=2022-05-01-preview", "/subscriptions/f3b08c7f-99a9-4a70-ba56-1e877abb77f7/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01"

    Invoke-AzureBatchRequest -batchRequest $batchRequest

    Creates batch request object containing both urls & run it.

    .EXAMPLE
    $subscriptionId = (Get-AzSubscription | ? State -EQ 'Enabled').Id

    New-AzureBatchRequest -url "https://management.azure.com/subscriptions/<placeholder>/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01" -placeholder $subscriptionId | Invoke-AzureBatchRequest

    Creates batch request object containing dynamically generated urls for every id in the $subscriptionId array & run it.

    .NOTES
    Uses undocumented API https://github.com/Azure/azure-sdk-for-python/issues/9271 :).
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject[]]$batchRequest,

        [switch] $dontBeautifyResult,

        [Alias("dontAddRequestId")]
        [switch] $dontAddRequestName,

        [switch] $separateErrors
    )

    begin {
        if ($PSCmdlet.MyInvocation.PipelineLength -eq 1) {
            Write-Verbose "Total number of requests to process is $($batchRequest.count)"
        }

        if ($dontBeautifyResult -and $dontAddRequestName) {
            Write-Verbose "'dontAddRequestName' parameter will be ignored, 'RequestName' property is not being added when 'dontBeautifyResult' parameter is used"
        }

        # api batch requests are limited to 20 requests
        $chunkSize = 20
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
                [System.Collections.Generic.List[Object]] $requestChunk
            )

            $duplicityId = $requestChunk | Select-Object -ExpandProperty Name | Group-Object | ? { $_.Count -gt 1 }
            if ($duplicityId) {
                throw "Batch requests must have unique names. Name $(($duplicityId | select -Unique) -join ', ') is there more than once"
            }

            Write-Debug ($requestChunk | ConvertTo-Json)

            Write-Verbose "Processing batch of $($requestChunk.count) request(s):`n$(($requestChunk | sort Url | % {" - $($_.Name) - $($_.Url)"} ) -join "`n")"

            #region process given chunk of batch requests
            $start = Get-Date

            $payload = @{
                requests = [array]$requestChunk
            }

            # invoke the batch
            $result = Invoke-AzRestMethod -Uri "https://management.azure.com/batch?api-version=2020-06-01" -Method POST -Payload ($payload | ConvertTo-Json -Depth 20) -ErrorAction Stop

            $responses = ($result.content | ConvertFrom-Json).responses

            #region return the output
            if ($dontBeautifyResult) {
                # return original response

                $responses
            } else {
                # return just actually requested data without batch-related properties and enhance the returned object with 'RequestName' property for easier filtering

                foreach ($response in $responses) {
                    $noteProperty = $null
                    if ($response.content) { $noteProperty = $response.content | Get-Member -MemberType NoteProperty }

                    # there was some error, no real values were returned, skipping
                    if ($response.httpStatusCode -in (400..509)) {
                        continue
                    }

                    # properties to return
                    $property = @("*")
                    if (!$dontAddRequestName) {
                        $property += @{n = 'RequestName'; e = { $response.Name } }
                    }

                    if ($response.content.value) {
                        # the result is in the 'value' property
                        $response.content.value | select -Property $property
                    } elseif ($response.content -and $noteProperty.Name -contains 'value') {
                        # the result is stored in 'value' property, but no results were returned, skipping
                    } elseif ($response.content -and $response.contentLength) {
                        # the result is in the 'content' property itself
                        if ($response.content.data -and $response.content.totalRecords -and $response.content.resultTruncated) {
                            # the result is in the 'data' property (Resource Graph KQL response)
                            $response.content.data | select -Property $property
                        } else {
                            $response.content | select -Property $property
                        }
                    } else {
                        # no results were returned, skipping
                    }
                }
            }
            #endregion return the output

            #region handle the responses based on their status code
            # load the next pages, retry throttled requests, repeat failed requests, ...

            $failedBatchJob = [System.Collections.Generic.List[Object]]::new()

            foreach ($response in $responses) {
                if ($response.httpStatusCode -in 200, 201, 204) {
                    # success

                    # not sure where the nextLink might be stored, so checking both 'body' and 'content'
                    $nextLink = $null
                    if ($response.body.nextLink) {
                        $nextLink = $response.body.nextLink
                    } elseif ($response.content.nextLink) {
                        $nextLink = $response.content.nextLink
                    }

                    if ($nextLink) {
                        # paginated (get remaining results by query returned NextLink URL)

                        Write-Verbose "Batch result for request '$($response.Name)' is paginated. Nextlink will be processed in the next batch"

                        # make a request object copy, so I can modify it without interfering with the original object
                        $nextLinkRequest = $requestChunk | ? Name -EQ $response.Name | ConvertTo-Json -Depth 10 | ConvertFrom-Json
                        # replace original URL with the nextLink
                        $nextLinkRequest.Url = $nextLink
                        # add the request for later processing
                        $extraRequestChunk.Add($nextLinkRequest)
                    }

                    $skipToken = $null
                    if ($skipToken = $response.content.'$skipToken') {
                        # paginated (get remaining results by using '$skipToken')

                        Write-Verbose "Batch result for request '$($response.Name)' is paginated (total records: $($response.content.totalRecords)). Request will be repeated with the returned `$skipToken"

                        # make a request object copy, so I can modify it without interfering with the original object
                        $nextPageRequest = $requestChunk | ? Name -EQ $response.Name | ConvertTo-Json -Depth 10 | ConvertFrom-Json
                        # set '$skipToken' option
                        if ($nextPageRequest.content.Options) {
                            if ($nextPageRequest.content.Options.'$skipToken') {
                                $nextPageRequest.content.Options.'$skipToken' = $skipToken
                            } else {
                                $nextPageRequest.content.Options | Add-Member -MemberType NoteProperty -Name '$skipToken' -Value $skipToken
                            }
                        } else {
                            $nextPageRequest.content | Add-Member -MemberType NoteProperty -Name Options -Value @{'$skipToken' = $skipToken }
                        }
                        # add the request for later processing
                        $extraRequestChunk.Add($nextPageRequest)
                    }
                } elseif ($response.httpStatusCode -eq 429) {
                    # throttled (will be repeated after given time)

                    $jobRetryAfter = $response.Headers.'Retry-After'
                    $throttledBatchRequest = $requestChunk | ? Name -EQ $response.Name

                    Write-Verbose "Batch request with Id: '$($throttledBatchRequest.Name)', Url:'$($throttledBatchRequest.Url)' was throttled, hence will be repeated after $jobRetryAfter seconds"

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
                } elseif ($response.httpStatusCode -in 500, 502, 503, 504) {
                    # some internal error on remote side (will be repeated)

                    $problematicBatchRequest = $requestChunk | ? Name -EQ $response.Name

                    Write-Verbose "Batch request with Id: '$($problematicBatchRequest.Name)', Url:'$($problematicBatchRequest.Url)' had internal error '$($response.httpStatusCode)', hence will be repeated"

                    $extraRequestChunk.Add($problematicBatchRequest)
                } else {
                    # failed

                    $failedBatchRequest = $requestChunk | ? Name -EQ $response.Name

                    $failedBatchJob.Add(
                        @{
                            Name       = $response.Name
                            Url        = $failedBatchRequest.Url
                            StatusCode = $response.httpStatusCode
                            Error      = $response.content.error.message
                            Object     = [ordered]@{
                                request  = $failedBatchRequest
                                response = $response
                            }
                        }
                    )
                }
            }

            # exit if critical failure occurred
            if ($failedBatchJob) {
                if ($separateErrors) {
                    # output errors one by one, so you can handle them separately if needed
                    $failedBatchJob | % {
                        #TIP only the first one will be returned if $ErrorActionPreference is set to stop!
                        Write-Error -Message "`nFailed batch request:`n$(" - Name: '$($_.Name)'", " - Url: '$($_.Url)'", " - StatusCode: '$($_.StatusCode)'", " - Error: '$($_.Error)'`n`n" -join "`n")" -ErrorId $_.StatusCode -Category "InvalidOperation" -TargetObject $_.Object
                    }
                } else {
                    #TIP all errors at once, because batch can contain non-related requests and if errorAction is set to stop, only the first error would be returned, which can be confusing
                    Write-Error "`nFollowing batch request(s) failed:`n`n$(($failedBatchJob | % {
                        " - Name: '$($_.Name)'", " - Url: '$($_.Url)'", " - StatusCode: '$($_.StatusCode)'", " - Error: '$($_.Error)'" -join "`n"
                    }) -join "`n`n")" -Category "InvalidOperation" -TargetObject $failedBatchJob.Object
                }
            }
            #endregion handle the responses based on their status code

            $end = Get-Date

            Write-Verbose "It took $((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds to process the batch"
            #endregion process given chunk of batch requests
        }
    }

    process {
        # check url validity
        $batchRequest.URL | % {
            if ($_ -notlike "https://management.azure.com/*" -and $_ -notlike "/*") {
                throw "url '$_' has to be relative (without the whole 'https://management.azure.com' part) or absolute!"
            }

            if ($_ -notmatch "/subscriptions/|\?" -and $_ -notmatch "/providers/|\?" -and $_ -notmatch "/resources/|\?" -and $_ -notmatch "/locations/|\?" -and $_ -notmatch "/tenants/|\?" -and $_ -notmatch "/bulkdelete/|\?") {
                throw "url '$_' is not valid. Is should starts with:`n/subscriptions, /providers, /resources, /locations, /tenants or /bulkdelete!"
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
                    Invoke-AzureBatchRequest -batchRequest $extraRequestChunk -dontBeautifyResult:$dontBeautifyResult

                    $extraRequestChunk.Clear()
                }

                # process throttled requests
                if ($throttledRequestChunk) {
                    Write-Warning "Processing $($throttledRequestChunk.count) throttled request(s) with $script:retryAfter seconds wait time"
                    Start-Sleep -Seconds $script:retryAfter
                    Invoke-AzureBatchRequest -batchRequest $throttledRequestChunk -dontBeautifyResult:$dontBeautifyResult

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
                Invoke-AzureBatchRequest -batchRequest $extraRequestChunk -dontBeautifyResult:$dontBeautifyResult
            }

            # process throttled requests
            if ($throttledRequestChunk) {
                Write-Warning "Processing $($throttledRequestChunk.count) throttled request(s) with $script:retryAfter seconds wait time"
                Start-Sleep -Seconds $script:retryAfter
                Invoke-AzureBatchRequest -batchRequest $throttledRequestChunk -dontBeautifyResult:$dontBeautifyResult
            }
        }
    }
}