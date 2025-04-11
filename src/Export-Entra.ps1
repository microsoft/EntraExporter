function Export-Entra {
    <#
    .SYNOPSIS
    Exports Entra's configuration and settings for a tenant.

    .DESCRIPTION
    This cmdlet reads the configuration information from the target Entra tenant and produces the output files in a target directory.

    .PARAMETER Path
    Specifies the directory path where the output files will be generated.

    .PARAMETER Type
    Specifies the type of objects to export. Default to Config which exports the key configuration settings of the tenant.

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
    Export-Entra -Path 'C:\EntraBackup\' -Type B2C

    Runs an export of all B2C settings.
    #>
    [CmdletBinding(DefaultParameterSetName = 'SelectTypes')]
    param (

        # The directory path where the output files will be generated.
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'AllTypes')]
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'SelectTypes')]
        [String]$Path,

        <# Specify the type of objects to export. Defaults to Config, which exports the key configuration settings of
        the tenant. The available types are:
            'All', 'Config', 'AccessReviews', 'ConditionalAccess', 'Users', 'Groups', 'Applications', 'ServicePrincipals',
            'B2C', 'B2B', 'PIM', 'PIMAzure', 'PIMAAD', 'AppProxy', 'Organization', 'Domains', 'EntitlementManagement',
            'Policies', 'AdministrativeUnits', 'SKUs', 'Identity', 'Roles', 'Governance', 'Devices', 'Teams', 'Sharepoint',
            'RoleManagement', 'DirectoryRoles', 'ExchangeRoles', 'IntuneRoles', 'CloudPCRoles', 'EntitlementManagementRoles',
            'Reports', and 'UsersRegisteredByFeatureReport'.
        #>
        [Parameter(ParameterSetName = 'SelectTypes')]
        [ValidateSet('All', 'Config', 'AccessReviews', 'ConditionalAccess', 'Users', 'Groups', 'Applications', 'ServicePrincipals', 'B2C', 'B2B', 'PIM', 'PIMAzure', 'PIMAAD', 'AppProxy', 'Organization', 'Domains', 'EntitlementManagement', 'Policies', 'AdministrativeUnits', 'SKUs', 'Identity', 'Roles', 'Governance', 'Devices', 'Teams', 'Sharepoint', 'RoleManagement', 'DirectoryRoles', 'ExchangeRoles', 'IntuneRoles', 'CloudPCRoles', 'EntitlementManagementRoles', 'Reports', 'UsersRegisteredByFeatureReport')]
        [String[]]$Type = 'Config',

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
        [object]$ExportSchema,

        # Specifies the schema to use for the export. If not specified, the default schema will be used.
        [Parameter(Mandatory = $false, ParameterSetName = 'AllTypes')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelectTypes')]
        [string[]]$Parents
    )

    if ($null -eq (Get-MgContext)) {
        Write-Error 'No active connection. Run Connect-EntraExporter or Connect-MgGraph to sign in and then retry.'
        break
    }
    if ($All) { $Type = @('All') }
    $global:Type = $Type #Used in places like Groups where Config flag will limit the resultset to just dynamic groups.

    if (!$ExportSchema) {
        $ExportSchema = Get-EEDefaultSchema
    }

    # aditional filters
    foreach ($entry in $ExportSchema) {
        $graphUri = Get-ObjectProperty $entry 'GraphUri'
        # filter out synced users or groups
        if ($CloudUsersAndGroupsOnly -and ($graphUri -in 'users', 'groups')) {
            if ([string]::IsNullOrEmpty($entry.Filter)) {
                $entry.Filter = 'onPremisesSyncEnabled ne true'
            } else {
                $entry.Filter = $entry.Filter + ' and (onPremisesSyncEnabled ne true)'
            }
        }
        # get all PIM elements
        if ($All -and ($graphUri -in 'privilegedAccess/aadroles/resources', 'privilegedAccess/azureResources/resources')) {
            $entry.Filter = $null
        }
    }

    foreach ($item in $ExportSchema) {
        $typeMatch = Compare-Object $item.Tag $Type -ExcludeDifferent -IncludeEqual
        $hasParents = $Parents -and $Parents.Count -gt 0
        if ( ($typeMatch)) {
            $outputFileName = Join-Path -Path $Path -ChildPath $item.Path

            $spacer = ''
            if ($hasParents) { $spacer = ''.PadRight($Parents.Count + 3, ' ') + $Parents[$Parents.Count - 1] }

            Write-Host "$spacer $($item.Path)"

            $command = Get-ObjectProperty $item 'Command'
            $graphUri = Get-ObjectProperty $item 'GraphUri'
            $apiVersion = Get-ObjectProperty $item 'ApiVersion'
            $ignoreError = Get-ObjectProperty $item 'IgnoreError'
            if (!$apiVersion) { $apiVersion = 'v1.0' }
            $resultItems = $null
            if ($command) {
                if ($hasParents) { $command += " -Parents $Parents" }
                $resultItems = Invoke-Expression -Command $command
            } else {
                if ($hasParents) { $graphUri = $graphUri -replace '{id}', $Parents[$Parents.Count - 1] }
                try {
                    $resultItems = Invoke-Graph $graphUri -Filter (Get-ObjectProperty $item 'Filter') -Select (Get-ObjectProperty $item 'Select') -QueryParameters (Get-ObjectProperty $item 'QueryParameters') -ApiVersion $apiVersion
                } catch {
                    $e = ''
                    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                        $e = $_.ErrorDetails.Message
                    }

                    if ($e.Contains($ignoreError) -or $e.Contains('Encountered an internal server error')) {
                        Write-Debug $_
                    } else {
                        Write-Error $_
                    }
                }
            }

            if ($outputFileName -match '\.json$') {
                if ($resultItems) {
                    $resultItems | ConvertTo-Json -Depth 100 | Out-File (New-Item -Path $outputFileName -Force)
                }
            } else {
                foreach ($resultItem in $resultItems) {
                    if (!$resultItem.PSObject.Properties['id']) {
                        continue
                    }
                    $itemOutputFileName = Join-Path -Path $outputFileName -ChildPath $resultItem.id
                    $parentOutputFileName = Join-Path $itemOutputFileName -ChildPath $resultItem.id
                    $resultItem | ConvertTo-Json -Depth 100 | Out-File (New-Item -Path "$($parentOutputFileName).json" -Force)
                    if ($item.ContainsKey('Children')) {
                        $itemParents = $Parents
                        $itemParents += $resultItem.Id
                        Export-Entra -Path $itemOutputFileName -Type $Type -ExportSchema $item.Children -Parents $itemParents
                    }
                }
            }
        }
    }
}
