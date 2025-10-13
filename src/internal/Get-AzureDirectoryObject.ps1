function Get-AzureDirectoryObject {
    <#
    .SYNOPSIS
    Alternative for Get-MgDirectoryObjectById if you want to avoid Microsoft.Graph.DirectoryObjects module dependency.

    .DESCRIPTION
    Alternative for Get-MgDirectoryObjectById if you want to avoid Microsoft.Graph.DirectoryObjects module dependency.

    .PARAMETER id
    ID(s) of the Azure object(s).

    .EXAMPLE
    Get-AzureDirectoryObject -Id 'a5834928-0f19-292d-4a69-3fbc98fd84ef'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias("ids")]
        [string[]] $id
    )

    if (!(Get-Command Get-MgContext -ErrorAction silentlycontinue) -or !(Get-MgContext)) {
        throw "$($MyInvocation.MyCommand): Authentication needed. Please call Connect-MgGraph."
    }

    # directoryObjects/microsoft.graph.getByIds can process only 1000 ids per request
    $chunkSize = 1000

    # calculate the total number of chunks
    $totalChunks = [Math]::Ceiling($id.Count / $chunkSize)

    # process each chunk
    for ($i = 0; $i -lt $totalChunks; $i++) {
        # calculate the start index of the current chunk
        $startIndex = $i * $chunkSize

        # extract the current chunk
        $currentChunk = $id[$startIndex..($startIndex + $chunkSize - 1)]

        # process the current chunk
        Write-Verbose "Processing chunk $($i + 1) with items: $($currentChunk -join ', ')"

        $body = @{
            "ids" = @($currentChunk)
        }

        Invoke-MgGraphRequest -Uri "v1.0/directoryObjects/microsoft.graph.getByIds" -Body ($body | ConvertTo-Json) -Method POST | Get-MgGraphAllPages | select *, @{Name = 'ObjectType'; Expression = { $_.'@odata.type' -replace "#microsoft.graph." } } -ExcludeProperty '@odata.type'
    }
}