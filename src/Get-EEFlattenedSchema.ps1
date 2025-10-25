<# 
 .Synopsis
    Recursively flattens the ExportSchema structure to get all entries including nested ones.
#>

function Get-EEFlattenedSchema {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ExportSchema
    )

    foreach ($entry in $ExportSchema) {
        $entry

        if ($entry.'Children') {
            Get-EEFlattenedSchema -ExportSchema $entry.Children
        }
    }
}