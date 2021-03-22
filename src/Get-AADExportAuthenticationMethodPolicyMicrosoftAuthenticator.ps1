<# 
 .Synopsis
  Get the Microsoft Authenticator authentication method policy

 .Description
  GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator
  https://docs.microsoft.com/en-us/graph/api/microsoftauthenticatorauthenticationmethodconfiguration-get

 .Example
  Get-AADExportAuthenticationMethodPolicyMicrosoftAuthenticator 
#>

Function Get-AADExportAuthenticationMethodPolicyMicrosoftAuthenticator {
  Invoke-Graph 'authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator'
}