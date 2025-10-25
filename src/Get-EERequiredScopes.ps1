<# 
 .Synopsis
  Gets the required scopes for schema

 .Description
  Gets the require scopes for schema

 .Example
  Get-EERequiredScopes
#>

function Get-EERequiredScopes {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)] 
        [ValidateSet('Delegated','Application')]
        [string]$PermissionType,

        [Parameter(Mandatory = $false)]
        [ObjectType[]]$Type,

        [Parameter(Mandatory = $false)]
        [object]$ExportSchema
    )

    if (!$ExportSchema) {
        $ExportSchema = Get-EEDefaultSchema
    }

    $scopeProperty = "DelegatedPermission"
    if ($PermissionType -eq "Application") {
        $scopeProperty = "ApplicationPermission"
    }

    $RequestedExportSchema = Get-EEFlattenedSchema -ExportSchema $ExportSchema

    if ($Type) {
        Write-Verbose "Filtering ExportSchema to only requested types: $($Type -join ', ')"
        # filter schema to only the requested types
        $RequestedExportSchema = $ExportSchema | ? { Compare-Object $_.Tag $Type -ExcludeDifferent -IncludeEqual }
    }

    $scopes = [System.Collections.Generic.List[Object]]::new()

    foreach ($entry in $RequestedExportSchema) {
        $entryScopes = $entry.$scopeProperty
        $command = $entry.Command
        $graphUri = $entry.GraphUri

        if ($Type -and ($entry.Tag -notin $Type) -and ($entry.Tag -ne 'All')) {
            Write-Verbose "Skipping entry with tag '$($entry.Tag)' because it is not in the requested types"
            continue
        }

        $entryType = "graphuri"
        $tocall = $graphUri
        if ($command) {
            $entryType = "command"
            $tocall = $command
        }

        if (!$entryScopes) {
            Write-Warning "Call to $entryType '$tocall' doesn't provide $PermissionType permissions"
        }
        
        foreach ($entryScope in $entryScopes) {
            if ($entryScope -notin $scopes) {
                $scopes.Add($entryScope)
            }
        }
    }

    $scopes | sort-object
}