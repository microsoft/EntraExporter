<#
.SYNOPSIS
    Create a final uri
#>
function New-FinalUri{
    [CmdletBinding()]
    param(
        # Graph endpoint such as "users".
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string[]] $RelativeUri,
        # Filters properties (columns).
        [Parameter(Mandatory = $false)]
        [string[]] $Select,
        # Filters results (rows). https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter
        [Parameter(Mandatory = $false)]
        [string] $Filter,
        # Parameters such as "$top".
        [Parameter(Mandatory = $false)]
        [hashtable] $QueryParameters
    )

    process {
        ## Process Each RelativeUri
        foreach ($uri in $RelativeUri) {
            Write-Verbose "Processing URI: $uri"
            $uriQueryEndpoint = New-Object System.UriBuilder -ArgumentList $uri

            ## Combine query parameters from URI and cmdlet parameters
            if ($uriQueryEndpoint.Query) {
                [hashtable] $finalQueryParameters = ConvertFrom-QueryString $uriQueryEndpoint.Query -AsHashtable
                if ($QueryParameters) {
                    foreach ($ParameterName in $QueryParameters.Keys) {
                        $finalQueryParameters[$ParameterName] = $QueryParameters[$ParameterName]
                    }
                }
            }
            elseif ($QueryParameters) { [hashtable] $finalQueryParameters = $QueryParameters }
            else { [hashtable] $finalQueryParameters = @{ } }
            if ($Select) { $finalQueryParameters['$select'] = $Select -join ',' }
            if ($Filter) { $finalQueryParameters['$filter'] = $Filter }
            $uriQueryEndpoint.Query = ConvertTo-QueryString $finalQueryParameters

            # New-GraphBatchRequest needs relative uri where < and > aren't URL encoded
            $uriQueryEndpoint.Uri.AbsoluteUri -replace "http://", "" -replace "%3C", "<" -replace "%3E", ">"
        }
    }
}