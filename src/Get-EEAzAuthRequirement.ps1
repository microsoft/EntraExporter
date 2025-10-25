<#
.SYNOPSIS
    Determines if Az authentication is required based on the requested export types and schema.
#>
function Get-EEAzAuthRequirement {
    [CmdletBinding(DefaultParameterSetName = 'SelectTypes')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'SelectTypes')]
        [ObjectType[]]$Type = 'Config',

        # Perform a full export of all available configuration item types.
        [Parameter(Mandatory = $true, ParameterSetName = 'AllTypes')]
        [switch]$All,

        # Specifies the schema to use for the export. If not specified, the default schema will be used.
        [Parameter(Mandatory = $false, ParameterSetName = 'AllTypes')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelectTypes')]
        [object]$ExportSchema
    )

    if ($All) { $Type = @('All') }

    if (!$ExportSchema) {
        $ExportSchema = Get-EEDefaultSchema
    }

    # filter schema to only the requested types
    $RequestedExportSchema = $ExportSchema | ? { Compare-Object $_.Tag $Type -ExcludeDifferent -IncludeEqual }

    #region determine if we need to authenticate to Graph and/or Az
    $FlattenedRequestedExportSchema = Get-EEFlattenedSchema -ExportSchema $RequestedExportSchema

    # determine if we need to authenticate to Az
    if ($FlattenedRequestedExportSchema.RequiresAzAuth) {
        return $true
    } else {
        return $false
    }
}