<# 
 .Synopsis
  Get users WHFB authentication method

 .Description
  GET /users/{id | userPrincipalName}/authentication/windowsHelloForBusinessMethods
  https://docs.microsoft.com/en-us/graph/api/windowshelloforbusinessauthenticationmethod-list

 .Example
  Get-AADExportAuthenticationMethodWindowsHelloForBusiness
#>

Function Get-AADExportAuthenticationMethodWindowsHelloForBusiness {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]$Parents
    )
    
    Invoke-Graph "users/$($Parents[0])/authentication/windowsHelloForBusinessMethods"
}