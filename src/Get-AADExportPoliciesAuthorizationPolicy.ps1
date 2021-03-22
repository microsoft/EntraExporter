<# 
 .Synopsis
  Represents a policy that can control Azure Active Directory authorization settings. It's a singleton that inherits from base policy type, and always exists for the tenant.

 .Description
  GET /policies/authorizationPolicy
  https://docs.microsoft.com/en-us/graph/api/resources/authorizationpolicy

 .Example
  Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy
#>

Function Get-AADExportPoliciesAuthorizationPolicy {
  Invoke-Graph 'policies/authorizationPolicy'
}