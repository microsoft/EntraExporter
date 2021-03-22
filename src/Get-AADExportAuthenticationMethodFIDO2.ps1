<# 
 .Synopsis
  Get users FIDO2 authentication method

 .Description
  GET /users/{id | userPrincipalName}/authentication/fido2Methods
  https://docs.microsoft.com/en-us/graph/api/fido2authenticationmethod-list

 .Example
  Get-AADExportAuthenticationMethodFIDO2
#>

Function Get-AADExportAuthenticationMethodFIDO2 {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]$Parents
    )
    
    Invoke-Graph "users/$($Parents[0])/authentication/fido2Methods"
}