<# 
 .Synopsis
  Get users Email authentication method

 .Description
  GET /users/{id | userPrincipalName}/authentication/emailMethods
  https://docs.microsoft.com/en-us/graph/api/emailauthenticationmethod-list

 .Example
  Get-AADExportAuthenticationMethodEmail
#>

Function Get-AADExportAuthenticationMethodEmail {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]$Parents
    )
    
    Invoke-Graph "users/$($Parents[0])/authentication/emailMethods"
}