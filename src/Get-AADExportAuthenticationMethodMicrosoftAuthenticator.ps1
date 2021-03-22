<# 
 .Synopsis
  Get users Microsoft Authenticator authentication method

 .Description
  GET /users/{id | userPrincipalName}/authentication/microsoftAuthenticatorMethods
  https://docs.microsoft.com/en-us/graph/api/microsoftauthenticatorauthenticationmethod-list

 .Example
  Get-AADExportAuthenticationMethodMicrosoftAuthenticator
#>

Function Get-AADExportAuthenticationMethodMicrosoftAuthenticator {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]$Parents
    )
    
    Invoke-Graph "users/$($Parents[0])/authentication/microsoftAuthenticatorMethods"
}