<# 
 .Synopsis
   Represents a policy that can control the lifetime of a JWT access token, an ID token or a SAML 1.1/2.0 token issued by Azure Active Directory (Azure AD). 

 .Description
  GET /policies/tokenLifetimePolicies
  https://docs.microsoft.com/en-us/graph/api/tokenlifetimepolicy-list?view=graph-rest-1.0&tabs=http

 .Example
  Get-AADExportPoliciesTokenLifetimePolicy
#>

Function Get-AADExportPoliciesTokenLifetimePolicy {
    Invoke-Graph 'policies/tokenLifetimePolicies'
  }