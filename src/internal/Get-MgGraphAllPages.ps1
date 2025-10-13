function Get-MgGraphAllPages {
    <#
    .SYNOPSIS
    Function make sure that all api call pages are returned a.k.a. all results.

    .DESCRIPTION
    Function make sure that all api call pages are returned a.k.a. all results.

    .PARAMETER NextLink
    For internal use.

    .PARAMETER SearchResult
    For internal use.

    .PARAMETER AsHashTable
    Switch to return results as hashtable.
    By default returns pscustomobject.

    .EXAMPLE
    Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps" | Get-MgGraphAllPages

    .NOTES
    Based on https://dev.to/celadin/get-mggraphallpages-the-mggraph-missing-command-45b5.
    #>

    [CmdletBinding(
        ConfirmImpact = 'Medium',
        DefaultParameterSetName = 'SearchResult'
    )]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'NextLink', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('@odata.nextLink')]
        [string] $NextLink
        ,
        [Parameter(ParameterSetName = 'SearchResult', ValueFromPipeline = $true)]
        [PSObject] $SearchResult
        ,
        [switch] $AsHashTable
    )

    begin {}

    process {
        if (!$SearchResult) { return }

        if ($PSCmdlet.ParameterSetName -eq 'SearchResult') {
            # Set the current page to the search result provided
            $page = $SearchResult

            # Extract the NextLink
            $currentNextLink = $page.'@odata.nextLink'

            # We know this is a wrapper object if it has an "@odata.context" property
            #if (Get-Member -InputObject $page -Name '@odata.context' -Membertype Properties) {
            # MgGraph update - MgGraph returns hashtables, and almost always includes .context
            # instead, let's check for nextlinks specifically as a hashtable key
            if ($page.ContainsKey('@odata.count')) {
                Write-Verbose "First page value count: $($Page.'@odata.count')"
            }

            if ($page.ContainsKey('@odata.nextLink') -or $page.ContainsKey('value')) {
                $values = $page.value
            } else {
                # this will probably never fire anymore, but maybe.
                $values = $page
            }

            # Output the values
            if ($values) {
                if ($AsHashTable) {
                    # Default returned objects are hashtables, so this makes for easy pscustomobject conversion on demand
                    $values | Write-Output
                } else {
                    $values | ForEach-Object { [pscustomobject]$_ }
                }
            }
        }

        while (-Not ([string]::IsNullOrWhiteSpace($currentNextLink))) {
            # Make the call to get the next page
            try {
                $page = Invoke-MgGraphRequest -Uri $currentNextLink -Method GET
            } catch {
                throw $_
            }

            # Extract the NextLink
            $currentNextLink = $page.'@odata.nextLink'

            # Output the items in the page
            $values = $page.value

            if ($page.ContainsKey('@odata.count')) {
                Write-Verbose "Current page value count: $($Page.'@odata.count')"
            }

            if ($AsHashTable) {
                # Default returned objects are hashtables, so this makes for easy pscustomobject conversion on demand
                $values | Write-Output
            } else {
                $values | ForEach-Object { [pscustomobject]$_ }
            }
        }
    }

    end {}
}