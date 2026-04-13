function SaveAs-SortedJSON {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [object]$Item,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
            if ($_ -match "\.\w+$") {
                $true
            } else {
                throw "$_ is not a valid JSON file path. Enter in 'c:\destination\file.json' format"
            }
        })]
        [string]$Path
    )

    begin {
        if (-not $Item) {
            return
        }
    }

    process {
        # RequestId, RequestName are batch api request ids aka unrelated
        $Item | Select-Object * -ExcludeProperty RequestId, RequestName | ConvertTo-OrderedDictionary | ConvertTo-Json -Depth 100 -WarningAction SilentlyContinue | Out-File (New-Item -Path $Path -Force)
    }
}