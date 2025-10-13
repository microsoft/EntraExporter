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
        # Specifies unique Id(s) for the URI endpoint. For example, users endpoint accepts Id or UPN.
        # [Parameter(Mandatory = $false)]
        # [string[]] $UniqueId,
        # Filters properties (columns).
        [Parameter(Mandatory = $false)]
        [string[]] $Select,
        # Filters results (rows). https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter
        [Parameter(Mandatory = $false)]
        [string] $Filter,
        # Parameters such as "$top".
        [Parameter(Mandatory = $false)]
        [hashtable] $QueryParameters,
        # Specifies consistency level.
        # [Parameter(Mandatory = $false)]
        # [string] $ConsistencyLevel = 'eventual',
        # Base URL for Microsoft Graph API.
        [Parameter(Mandatory = $false)]
        [uri] $GraphBaseUri
    )

    begin {
        if(!$GraphBaseUri){
            if(!(Test-Path variable:global:GraphBaseUri)){
                $global:GraphBaseUri = $((Get-MgEnvironment -Name (Get-MgContext).Environment).GraphEndpoint)
            }
            $GraphBaseUri = $global:GraphBaseUri
        }
    }

    process {
        ## Initialize
        # if (!$UniqueId) { [string[]] $UniqueId = '' }

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

            ## Invoke graph requests individually or save for single batch request
            # foreach ($id in $UniqueId) {
            #     $uriQueryEndpointFinal = New-Object System.UriBuilder -ArgumentList $uriQueryEndpoint.Uri
            #     $uriQueryEndpointFinal.Path = ([IO.Path]::Combine($uriQueryEndpointFinal.Path, $id))

            #     ## Create batch request entry
            #     $request = New-Object PSObject -Property @{
            #         id      = $listRequests.Count #(New-Guid).ToString()
            #         method  = 'GET'
            #         url     = $uriQueryEndpointFinal.Uri.AbsoluteUri -replace ('{0}{1}/' -f $GraphBaseUri.AbsoluteUri, $ApiVersion)
            #         headers = @{ ConsistencyLevel = $ConsistencyLevel }
            #     }
            #     $listRequests.Add($request)
            # }

            $uriQueryEndpoint.Uri.AbsoluteUri -replace "http://"
            # $uriQueryEndpointFinal = New-Object System.UriBuilder -ArgumentList $uriQueryEndpoint.Uri
            # $uriQueryEndpointFinal | fl *
            # $uriQueryEndpointFinal.Path = ([IO.Path]::Combine($uriQueryEndpointFinal.Path, $id))
            # $uriQueryEndpointFinal | fl *
            # $uriQueryEndpointFinal.Uri.AbsoluteUri -replace ('{0}/' -f $GraphBaseUri.AbsoluteUri)
        }
    }
}