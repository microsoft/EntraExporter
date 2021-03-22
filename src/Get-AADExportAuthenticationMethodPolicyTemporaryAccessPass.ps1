<# 
 .Synopsis
  Get the Temporary Access Pass authentication method policy

 .Description
  GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass
  https://docs.microsoft.com/en-us/graph/api/temporaryaccesspassauthenticationmethodconfiguration-get

 .Example
  Get-AADExportAuthenticationMethodPolicyTemporaryAccessPass
#>

Function Get-AADExportAuthenticationMethodPolicyTemporaryAccessPass {
  Invoke-Graph 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass'
}