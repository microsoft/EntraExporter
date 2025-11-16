$global:TenantID = $null
<#
.SYNOPSIS
    Authenticate against Graph Api and/or Azure using delegated permissions (as user).
.DESCRIPTION
    Authenticate against Graph Api and/or Azure using delegated permissions (as user).

    To authenticate using a certificate or client secret, use Connect-MgGraph or Connect-AzAccount directly.
.EXAMPLE
    PS C:\>Connect-EntraExporter
    Connect to home tenant of authenticated user.
.EXAMPLE
    PS C:\>Connect-EntraExporter -TenantId 3043-343434-343434 -Type Users, Groups, Devices
    Connect to a specific Tenant. Correct delegated Graph scopes will be automatically requested based on the types specified.
#>
function Connect-EntraExporter {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId = 'common',

        [Parameter(Mandatory=$false)]
            [ArgumentCompleter( {
                param ( $CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters )
                (Get-MgEnvironment).Name
            } )]
        [string]$Environment = 'Global',

        [Parameter(ParameterSetName = 'SelectTypes', Mandatory = $false)]
        [ObjectType[]]$Type = 'Config',

        # Perform a full export of all available configuration item types.
        [Parameter(ParameterSetName = 'AllTypes', Mandatory = $true)]
        [switch]$All,

        # Specifies the schema to use for the export. If not specified, the default schema will be used.
        [object]$ExportSchema
    )

    if ($All) { $Type = @('All') }

    if (!$ExportSchema) {
        $ExportSchema = Get-EEDefaultSchema
    }

    # filter schema to only the requested types
    $RequestedExportSchema = $ExportSchema | Where-Object { Compare-Object $_.Tag $Type -ExcludeDifferent -IncludeEqual }

    #region determine if we need to authenticate to Graph and/or Az
    $FlattenedRequestedExportSchema = Get-EEFlattenedSchema -ExportSchema $RequestedExportSchema

    # determine if we need to authenticate to Graph
    $RequiresGraphAuthentication = $false
    if ($FlattenedRequestedExportSchema.GraphUri) {
        $RequiresGraphAuthentication = $true
    }

    # determine if we need to authenticate to Az
    $RequiresAzAuthentication = Get-EEAzAuthRequirement -ExportSchema $RequestedExportSchema -Type $Type
    #endregion determine if we need to authenticate to Graph and/or Az

    # connect to Az as needed
    #TIP in general it is better to authenticate first to Az module and then to Mg module because of dll assembly conflicts
    if ($RequiresAzAuthentication) {
        # transform Graph environment name to the Azure one
        switch ($Environment) {
            {$_ -in 'USGovDoD', 'USGov'} { $AzureEnvironment = 'AzureUSGovernment' }
            'Global'    { $AzureEnvironment = 'AzureCloud' }
            'China'     { $AzureEnvironment = 'AzureChinaCloud' }
            'Germany'   { throw "'Germany' is deprecated environment." }
            default     { throw "Unknown environment '$Environment'." }
        }

        Connect-AzAccount -Tenant $TenantId -Environment $AzureEnvironment
    }

    # connect to Graph as needed
    if ($RequiresGraphAuthentication) {
        $graphScope = Get-EERequiredScopes -PermissionType 'Delegated' -ExportSchema $RequestedExportSchema

        Write-Verbose "Connecting to Graph with scopes: $($graphScope -join ', ')"
        Connect-MgGraph -TenantId $TenantId -Environment $Environment -Scopes $graphScope

        $global:TenantID = (Get-MgContext).TenantId
    }
}