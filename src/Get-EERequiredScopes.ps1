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
        [object]$ExportSchema
    )

    if (!$ExportSchema) {
        $ExportSchema = Get-EEDefaultSchema
    }

    $scopeProperty = "DelegatedPermission"
    if ($PermissionType -eq "Application") {
        $scopeProperty = "ApplicationPermission"
    }

    $scopes = @()
    foreach($entry in $ExportSchema) {
        $entryScopes = Get-ObjectProperty $entry $scopeProperty
        $command = Get-ObjectProperty $entry 'Command'
        $graphUri = Get-ObjectProperty $entry 'GraphUri'
        $entryType = "graphuri"
        $tocall = $graphUri
        if ($command) {
            $entryType = "command"
            $tocall = $command
        }

        if (!$entryScopes) {
            write-warning "call to $entryType '$tocall' doesn't provide $PermissionType permissions"
        }
        
        foreach ($entryScope in $entryScopes) {
            if ($entryScope -notin $scopes) {
                $scopes += $entryScope
            }
        }
        if ($entry.ContainsKey('Children')) {
            $childScopes = Get-EERequiredScopes -PermissionType $PermissionType -ExportSchema $entry.Children
            foreach ($entryScope in $childScopes) {
                if ($entryScope -notin $scopes) {
                    $scopes += $entryScope
                }
            }
        }
    }

    $scopes | sort-object
}