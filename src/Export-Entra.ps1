function Export-Entra {
    <#
    .SYNOPSIS
    Exports Entra's configuration and settings for a tenant.

    .DESCRIPTION
    This cmdlet reads the configuration information from the target Entra tenant and produces the output files in a target directory.

    .PARAMETER Path
    Specifies the directory path where the output files will be generated.

    .PARAMETER Type
    Specifies the type of objects to export. 
    Default to Config which exports the key configuration settings of the tenant.

    The available types are:
        'AccessPolicies','AccessReviews','AdministrativeUnits','All','Applications','AppProxy','B2B','B2C','CloudPCRoles','ConditionalAccess','Config','Devices','Directory','DirectoryRoles','Domains','EntitlementManagement','EntitlementManagementRoles','ExchangeRoles','Governance','Groups','IAM','Identity','IntuneRoles','Organization','PIM','PIMDirectoryRoles','PIMGroups','PIMResources','Policies','Reports','RoleManagement','Roles','ServicePrincipals','Sharepoint','SKUs','Teams','Users','UsersRegisteredByFeatureReport'.

    To see what each type exports, check src\Get-EEDefaultSchema.ps1 and check the 

    .PARAMETER All
    If specified performs a full export of all objects and configuration in the tenant.

    .PARAMETER CloudUsersAndGroupsOnly
    Excludes synched on-premises users and groups from the export. Only cloud-managed users and groups will be included.

    .EXAMPLE
    Export-Entra -Path 'C:\EntraBackup\'

    Runs a default export and includes the key tenant configuration settings. Does not include large data collections such as users, static groups, applications, service principals, etc.

    .EXAMPLE
    Export-Entra -Path 'C:\EntraBackup\' -All

    Runs a full export of all objects and configuration settings.

    .EXAMPLE
    Export-Entra -Path 'C:\EntraBackup\' -All -CloudUsersAndGroupsOnly

    Runs a full export but excludes on-prem synced users and groups.

    .EXAMPLE
    Export-Entra -Path 'C:\EntraBackup\' -Type ConditionalAccess, AppProxy

    Runs an export that includes just the Conditional Access and Application Proxy settings.

    .EXAMPLE
    $exportTypes = @('Users', 'Groups', 'Devices', 'B2C')

    # authenticate using user credentials
    Connect-EntraExporter -Type $exportTypes

    # export data
    Export-Entra -Path 'C:\EntraBackup\' -Type $exportTypes

    Authenticate interactively (user auth) and run an export of selected settings.

    .EXAMPLE
    $exportTypes = @('Users', 'Groups', 'Devices', 'B2C')
    $requiredGraphScopes = Get-EERequiredScopes -Type $exportTypes -PermissionType Application

    # determine if we need to authenticate to Graph
    if ($requiredGraphScopes) {
        "Following application type scopes are required: $($requiredGraphScopes -join ', ') !"

        # authenticate using managed identity
        Connect-MgGraph -Identity
    }

    # determine if we need to authenticate to Az
    if (Get-EEAzAuthRequirement -Type $exportTypes) {
        # authenticate using managed identity
        Connect-AzAccount -Identity
    }

    # export data
    Export-Entra -Path 'C:\EntraBackup\' -Type $exportTypes

    Authenticate using managed identity and run an export of selected settings.
    #>
    [CmdletBinding(DefaultParameterSetName = 'SelectTypes')]
    param (

        # The directory path where the output files will be generated.
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'AllTypes')]
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'SelectTypes')]
        [String]$Path,

        [Parameter(ParameterSetName = 'SelectTypes')]
        [ObjectType[]]$Type = 'Config',

        # Perform a full export of all available configuration item types.
        [Parameter(ParameterSetName = 'AllTypes')]
        [switch]$All,

        # Exclude synced on-premises users and groups from the Entra export. Only cloud-managed users and groups will be included.
        [Parameter(Mandatory = $false, ParameterSetName = 'AllTypes')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelectTypes')]
        [switch]$CloudUsersAndGroupsOnly,

        # Specifies the schema to use for the export. If not specified, the default schema will be used.
        [Parameter(Mandatory = $false, ParameterSetName = 'AllTypes')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelectTypes')]
        [object]$ExportSchema
    )

    $mgContext = Get-MgContext

    if (!$mgContext) {
        throw 'No active connection. Run Connect-EntraExporter or Connect-MgGraph to sign in and then retry.'
    }

    if ($All) { $Type = @('All') }
    $global:Type = $Type #Used in places like Groups where Config flag will limit the resultset to just dynamic groups.

    if (!$ExportSchema) {
        $ExportSchema = Get-EEDefaultSchema
    }

    $authScope = $mgContext.AuthType
    if ($authScope -eq "Delegated") {
        $schemaScopeType = "DelegatedPermission"
    } else {
        $schemaScopeType = "ApplicationPermission"
    }

    # modify schema filter property if needed
    foreach ($entry in $ExportSchema) {
        $graphUri = Get-ObjectProperty $entry "GraphUri"
        # filter out synced users or groups
        if ($CloudUsersAndGroupsOnly -and ($graphUri -in "users","groups")) {
            if([string]::IsNullOrEmpty($entry.Filter)){
                $entry.Filter = "onPremisesSyncEnabled ne true"
            }
            else {
                $entry.Filter = $entry.Filter + " and (onPremisesSyncEnabled ne true)"
            }
        }
    }

    #region helper functions
    function _randomizeRequestId {
        <#
        Adds a random number to the request ID to avoid duplicates in batch requests.

        Request ID in batch requests must be unique. I am using 'Path' property from $ExportSchema as the request ID.
        However, there can be multiple $ExportSchema items with the same path (e.g. 'Groups' in this case) which would lead to duplicated request IDs in the batch request and failure of the whole batch.
        To avoid this, I am appending a random number to the request ID.
        #>

        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$requestId
        )

        # add a random number to avoid duplicated ids in batch requests
        $requestId + "%%%" + (Get-Random) + "%%%"
    }

    function _normalizeRequestId {
        <#
        Removes the randomization string (added to the request ID to avoid duplicates in batch requests).
        #>

        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$requestId
        )

        # remove the random string added to avoid duplicated ids in batch requests
        $requestId -replace "\%\%\%\d+\%\%\%", ""
    }

    function _processBatchErrors {
        param(
            [array]$requestErrors,
            [array]$requestedExportSchema
        )

        foreach ($err in $requestErrors) {
            if ($err.Exception.Source -eq "BatchRequest") {
                # batch request errors

                # it happens that before starting to retrieve app details, the app is deleted
                # in this case we get 404 error which we can safely ignore
                if ($err.TargetObject.response.status -in 400,404) {
                    Write-Verbose "Ignoring request with id '$($err.TargetObject.request.id)' as it returned status code $($err.TargetObject.response.status)"
                    continue
                }

                # if ($err.TargetObject.response.status -eq 403) {
                #     Write-Error "Ignoring request with id '$($err.TargetObject.request.id)' as it returned status code $($err.TargetObject.response.status)"
                #     continue
                # }

                # ignore errors specified in the schema
                $requestedExportSchema.IgnoreError | select -Unique | % {
                    if ($err.Exception.Message -like "*$_*") {
                        Write-Verbose "Ignoring request with id '$($err.TargetObject.request.id)' as it returned error to ignore '$_'"
                        continue
                    }
                }

                # ignore custom errors
                "The request did not have a subscription or a valid tenant level resource provider", "The filter 'applicableToScope eq ''' is not supported" | % {
                    if ($err.Exception.Message -like "*$_*") {
                        Write-Verbose "Ignoring request with id '$($err.TargetObject.request.id)' as it returned error to ignore '$_'"
                        continue
                    }
                }

                Write-Error $err
                break
            } else {
                # other non-batch-related errors
                Write-Error $err
                break
            }
        }
    }

    function _processChildrenRecursive {
        param(
            [array]$schemaItems,
            [string]$basePath,
            [array]$parentIds,
            [ref]$results,
            [ref]$batchRequestStableApi,
            [ref]$batchRequestBetaApi
        )

        foreach ($item in $schemaItems) {
            Write-Warning "Processing child '$($item.GraphUri)' ($($item.Path))"

            if (!$item.$schemaScopeType) {
                Write-Warning " - Skipping as it doesn't support '$schemaScopeType'"
                continue
            }

            $command = Get-ObjectProperty $item 'Command'
            $graphUri = Get-ObjectProperty $item 'GraphUri'
            $apiVersion = Get-ObjectProperty $item 'ApiVersion'
            $ignoreError = Get-ObjectProperty $item 'IgnoreError'
            $children = Get-ObjectProperty $item 'Children'
            if (!$apiVersion) { $apiVersion = 'v1.0' }

            if ($command) {
                $commandParams = @{}

                # define how the command should be invoked
                switch ($command) {
                    {$command -in 'Get-AccessPackageAssignmentPolicies', 'Get-AccessPackageAssignments', 'Get-AccessPackageResourceScopes'} {
                        $commandParams = @{
                            Parents = $parentIds
                            BasePath = $basePath
                        }
                    }

                    default {
                        throw "Unknown command '$command'"
                    }
                }

                # invoke the command with splatting
                & $command @commandParams
            }
            else {
                $uri = New-FinalUri -RelativeUri $graphUri -Select (Get-ObjectProperty $item 'Select') -QueryParameters (Get-ObjectProperty $item 'QueryParameters') -Filter (Get-ObjectProperty $item 'Filter')

                $parentIds | % {
                    if ($item.Path -match "\.json$") {
                        $outputFileName = Join-Path -Path $basePath -ChildPath $item.Path
                    } else {
                        $outputFileName = Join-Path -Path $basePath -ChildPath $_
                        $outputFileName = Join-Path -Path $outputFileName -ChildPath $item.Path
                    }
                    # batch request id cannot contain '\' character
                    $id = $outputFileName -replace '\\', '/'

                    # to avoid duplicated ids in batch request if there are multiple $ExportSchema items with the same path ('Groups' in this case)
                    $id = _randomizeRequestId $id

                    Write-Verbose "Adding request '$uri' with id '$id' to the batch"

                    $request = New-GraphBatchRequest -Url $uri -Id $id -placeholder $_ -header @{ ConsistencyLevel = 'eventual' }

                    if ($apiVersion -eq 'beta') {
                        $batchRequestBetaApi.Value.Add($request)
                    }
                    else {
                        $batchRequestStableApi.Value.Add($request)
                    }
                }
            }

            # recursively process children if they exist
            if ($children) {
                # for grandchildren, we need to collect the parent IDs from the results
                $childBasePath = if ($item.Path -match "\.json$") {
                    $basePath
                } else {
                    Join-Path -Path $basePath -ChildPath $item.Path
                }

                # we'll process these after the current batch is executed and results are available
                $script:childrenToProcess.Add(@{
                    Children = $children
                    BasePath = $childBasePath
                    ParentPath = "$($item.Path)*"
                })
            }
        }
    }

    function _executeBatchRequests {
        param(
            [ref]$batchRequestStableApi,
            [ref]$batchRequestBetaApi,
            [ref]$results,
            [array]$requestedExportSchema
        )

        # execute v1.0 API batch requests
        if ($batchRequestStableApi.Value.Count -gt 0) {
            Write-Warning "Processing $($batchRequestStableApi.Value.count) v1.0 API requests"
            $batchResults = Invoke-GraphBatchRequest -batchRequest $batchRequestStableApi.Value -separateErrors -ErrorAction SilentlyContinue -ErrorVariable requestErrors -WarningAction SilentlyContinue

            if ($batchResults) {
                $results.Value.AddRange(@($batchResults))
            }

            _processBatchErrors -requestErrors $requestErrors -requestedExportSchema $requestedExportSchema
            $batchRequestStableApi.Value.Clear()
        }

        # execute beta API batch requests
        if ($batchRequestBetaApi.Value.Count -gt 0) {
            Write-Warning "Processing $($batchRequestBetaApi.Value.count) beta API requests"
            $batchResults = Invoke-GraphBatchRequest -batchRequest $batchRequestBetaApi.Value -graphVersion beta -separateErrors -ErrorAction SilentlyContinue -ErrorVariable requestErrors -WarningAction SilentlyContinue

            if ($batchResults) {
                $results.Value.AddRange(@($batchResults))
            }

            _processBatchErrors -requestErrors $requestErrors -requestedExportSchema $requestedExportSchema
            $batchRequestBetaApi.Value.Clear()
        }
    }
    #endregion helper functions

    #region process all schema items recursively
    $results = [System.Collections.Generic.List[Object]]::new()
    $batchRequestStableApi = [System.Collections.Generic.List[Object]]::new()
    $batchRequestBetaApi = [System.Collections.Generic.List[Object]]::new()
    $script:childrenToProcess = [System.Collections.Generic.List[Object]]::new()

    $requestedExportSchema = $ExportSchema | ? { Compare-Object $_.Tag $Type -ExcludeDifferent -IncludeEqual }

    # process root level items
    foreach ($item in $requestedExportSchema) {
        $outputFileName = Join-Path -Path $Path -ChildPath $item.Path

        Write-Warning "Processing parent '$($item.GraphUri)' ($($item.Path))"

        if (!$item.$schemaScopeType) {
            Write-Warning "Skipping as it doesn't support '$schemaScopeType'"
            continue
        }

        $command = Get-ObjectProperty $item 'Command'
        $graphUri = Get-ObjectProperty $item 'GraphUri'
        $apiVersion = Get-ObjectProperty $item 'ApiVersion'
        $ignoreError = Get-ObjectProperty $item 'IgnoreError'
        $children = Get-ObjectProperty $item 'Children'
        if (!$apiVersion) { $apiVersion = 'v1.0' }

        if($command) {
            $commandParams = @{}

            switch ($command) {
                'Get-AzureResourceIAMData' {
                    $commandParams.RootFolder = $outputFileName
                }

                'Get-AzurePIMDirectoryRoles' {
                    $commandParams.RootFolder = $outputFileName
                }

                'Get-AzurePIMResources' {
                    $commandParams.RootFolder = $outputFileName
                }

                'Get-AzurePIMGroups' {
                    $commandParams.RootFolder = $outputFileName
                }

                'Get-AzureResourceAccessPolicies' {
                    $commandParams.RootFolder = $outputFileName
                }

                default {
                    throw "Unknown command '$command'"
                }
            }

            # invoke the command with splatting
            & $command @commandParams
        }
        else {
            $uri = New-FinalUri -RelativeUri $graphUri -Select (Get-ObjectProperty $item 'Select') -QueryParameters (Get-ObjectProperty $item 'QueryParameters') -Filter (Get-ObjectProperty $item 'Filter')
            
            # batch request id cannot contain '\' character
            $id = $outputFileName -replace '\\', '/'

            # to avoid duplicated ids in batch request if there are multiple $ExportSchema items with the same path ('Groups' in this case)
            $id = _randomizeRequestId $id

            Write-Verbose "Adding request '$uri' with id '$id' to the batch"

            $request = New-GraphBatchRequest -Url $uri -Id $id -header @{ ConsistencyLevel = 'eventual' }

            if ($apiVersion -eq 'beta') {
                $batchRequestBetaApi.Add($request)
            }
            else {
                $batchRequestStableApi.Add($request)
            }
        }

        # track children for later processing
        if ($children) {
            $script:childrenToProcess.Add(@{
                Children = $children
                BasePath = Join-Path -Path $Path -ChildPath $item.Path
                ParentPath = $item.Path
            })
        }
    }

    # execute root level batch requests
    _executeBatchRequests -batchRequestStableApi ([ref]$batchRequestStableApi) -batchRequestBetaApi ([ref]$batchRequestBetaApi) -results ([ref]$results) -requestedExportSchema $requestedExportSchema

    # process children recursively
    while ($script:childrenToProcess.Count -gt 0) {
        $currentBatch = $script:childrenToProcess
        $script:childrenToProcess = [System.Collections.Generic.List[Object]]::new()

        foreach ($childGroup in $currentBatch) {
            Write-Verbose "Looking for results for parent with path '$($childGroup.ParentPath)'"

            $parentResult = $results | Where-Object {
                $normalizedRequestId = _normalizeRequestId $_.RequestId
                $normalizedRequestId -eq ($childGroup.BasePath -replace "\\", "/") -or
                $normalizedRequestId -like ("$($childGroup.ParentPath)*" -replace "\\", "/")
            }

            if (!$parentResult) {
                Write-Verbose "Parent '$($childGroup.ParentPath)' doesn't contain any data, skipping children retrieval"
                continue
            }

            # there can be multiple parent items with same Path, remove duplicates just in case
            $parentIds = $parentResult.Id | select -Unique
            Write-Warning "Processing children results for parent '$($childGroup.ParentPath)' ($($parentIds.count))"

            _processChildrenRecursive -schemaItems $childGroup.Children -basePath $childGroup.BasePath -parentIds $parentIds -results ([ref]$results) -batchRequestStableApi ([ref]$batchRequestStableApi) -batchRequestBetaApi ([ref]$batchRequestBetaApi)
        }

        # execute batch requests for this level
        _executeBatchRequests -batchRequestStableApi ([ref]$batchRequestStableApi) -batchRequestBetaApi ([ref]$batchRequestBetaApi) -results ([ref]$results) -requestedExportSchema $requestedExportSchema
    }
    #endregion process all schema items recursively

    #region output results
    foreach ($item in $results) {
        if (!(Get-ObjectProperty $item 'Id')){
            <#
            In some special cases it can happen that 'id' property is missing like:

            isEnabled             : True
            notifyReviewers       : True
            remindersEnabled      : False
            requestDurationInDays : 14
            version               : 0
            reviewers             : {@{query=/v1.0/groups/b3dbfaaa-4447-4ebe-8d28-c885c851828b/transitiveMembers/microsoft.graph.user; queryType=MicrosoftGraph; queryRoot=}, @{query=/beta/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'; queryType=MicrosoftGraph; queryRoot=}}
            RequestId             : C:/temp/bkp3/Policies/AdminConsentRequestPolicy

            tenantId                     : 6abd85ef-c27c-4e71-b000-4c68074a6f7b
            isServiceProvider            : True
            isInMultiTenantOrganization  : False
            inboundTrust                 :
            b2bCollaborationOutbound     :
            b2bCollaborationInbound      :
            b2bDirectConnectOutbound     :
            b2bDirectConnectInbound      :
            tenantRestrictions           :
            automaticUserConsentSettings : @{inboundAllowed=; outboundAllowed=}
            RequestId                    : C:/temp/bkp3/Policies/CrossTenantAccessPolicy/Partners
            #>

            $itemId = ($item.RequestId -split "/")[-1]
            # remove the random number added to avoid duplicated ids in batch requests
            $itemId = _normalizeRequestId $itemId

            Write-Verbose ($item | convertto-json)
            Write-Warning "Result without 'id' property, using '$itemId' instead (RequestId '$($item.RequestId)')!"
        } else {
            $itemId = $item.id
        }

        if (!$item.RequestId) {
            $item
            throw "Item without RequestId. Shouldn't happen!"
        }

        $outputFileName = $item.RequestId -replace "/", "\"
        # remove the random number added to avoid duplicated ids in batch requests
        $outputFileName = _normalizeRequestId $outputFileName

        if ($outputFileName -notmatch "\.json$") {
            $outputFileName = Join-Path (Join-Path -Path $outputFileName -ChildPath $itemId) -ChildPath "$itemId.json"
        }

        if ($outputFileName.Length -gt 255 -and (Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -ErrorAction SilentlyContinue) -ne 1) {
            throw "Output file path '$outputFileName' is longer than 255 characters. Enable long path support to continue!"
        }

        $item | select * -ExcludeProperty RequestId | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
    }
    #endregion output results
}