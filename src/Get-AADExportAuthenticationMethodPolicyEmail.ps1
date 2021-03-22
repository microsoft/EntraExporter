<# 
 .Synopsis
  Get the Email authentication method policy

 .Description
  GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/email
  https://docs.microsoft.com/en-us/graph/api/emailauthenticationmethodconfiguration-get

 .Example
  Get-AADExportAuthenticationMethodPolicyEmail
#>

Function Get-AADExportAuthenticationMethodPolicyEmail {
  Invoke-Graph 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/email'
}