<# 
 .Synopsis
   Represents the policy to specify the characteristics of SAML tokens issued by Azure AD. 

 .Description
  GET /policies/tokenIssuancePolicies
  https://docs.microsoft.com/en-us/graph/api/resources/tokenissuancepolicy?view=graph-rest-1.0

 .Example
  Get-AADExportPoliciesTokenIssuancePolicy
#>

Function Get-AADExportPoliciesTokenIssuancePolicy {
    Invoke-Graph 'policies/tokenIssuancePolicies'
  }