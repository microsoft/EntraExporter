<# 
 .Synopsis
  Get the FIDO2 authentication method policy

 .Description
  GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2
  https://docs.microsoft.com/en-us/graph/api/fido2authenticationmethodconfiguration-get

 .Example
  Get-AADExportAuthenticationMethodPolicyFIDO2
#>

Function Get-AADExportAuthenticationMethodPolicyFIDO2 {
  Invoke-Graph 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'
}