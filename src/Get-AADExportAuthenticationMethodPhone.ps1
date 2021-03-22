<# 
 .Synopsis
  Get users Phone authentication method

 .Description
  GET /users/{id | userPrincipalName}/authentication/phoneMethods
  https://docs.microsoft.com/en-us/graph/api/authentication-list-phonemethods

 .Example
  Get-AADExportAuthenticationMethodPhone
#>

Function Get-AADExportAuthenticationMethodPhone {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]$Parents
    )
    
    Invoke-Graph "users/$($Parents[0])/authentication/phoneMethods"
}