<# 
 .Synopsis
  Get users Password authentication method

 .Description
  GET /users/{id | userPrincipalName}/authentication/passwordMethods
  https://docs.microsoft.com/en-us/graph/api/authentication-list-passwordmethods

 .Example
  Get-AADExportAuthenticationMethodPassword
#>

Function Get-AADExportAuthenticationMethodPassword {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]$Parents
    )
    
    Invoke-Graph "users/$($Parents[0])/authentication/passwordMethods"
}