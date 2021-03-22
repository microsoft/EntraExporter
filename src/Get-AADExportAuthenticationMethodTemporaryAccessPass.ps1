<# 
 .Synopsis
  Get users TemporaryAccessPass authentication method

 .Description
  GET /users/{id | userPrincipalName}/authentication/temporaryAccessPassMethods
  https://docs.microsoft.com/en-us/graph/api/temporaryAccessPassauthenticationmethod-list

 .Example
  Get-AADExportAuthenticationMethodTemporaryAccessPass
#>

Function Get-AADExportAuthenticationMethodTemporaryAccessPass {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]$Parents
    )
    
    Invoke-Graph "users/$($Parents[0])/authentication/temporaryAccessPassMethods"
}