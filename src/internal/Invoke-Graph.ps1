<#
.SYNOPSIS
    Run a Microsoft Graph Command
#>
function Invoke-Graph{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $false)]
        [string]$Body,
        [Parameter(Mandatory = $false)]
        [string]$Method = 'GET'
    )
    
    if(!(Get-MgContext)){
        Write-Error "You must call the Connect-AADExporter cmdlet before calling any other cmdlets." -ErrorAction Stop
    }
    $uri = 'https://graph.microsoft.com/beta' + $uri
    if($Method -eq 'GET'){
        return Invoke-GraphRequest -Uri $uri -Method $method
    }
    else {
        return Invoke-GraphRequest -Uri $uri -Body $body -Method $method
    }

}