<# 
 .Synopsis
  Get the SMS authentication method policy

 .Description
  GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms
  https://docs.microsoft.com/en-us/graph/api/smsauthenticationmethodconfiguration-get

 .Example
  Get-AADExportAuthenticationMethodPolicySMS
#>

Function Get-AADExportAuthenticationMethodPolicySMS {
  Invoke-Graph 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms'
}