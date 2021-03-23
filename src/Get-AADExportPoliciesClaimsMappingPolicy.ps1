<# 
 .Synopsis
   Represents the claim-mapping policies for WS-Fed, SAML, OAuth 2.0, and OpenID Connect protocols, for tokens issued to a specific application.

 .Description
  GET /policies/claimsMappingPolicies
  https://docs.microsoft.com/en-us/graph/api/resources/claimsmappingpolicy?view=graph-rest-1.0
 .Example
  Get-AADExportPoliciesClaimsMappingPolicy
#>

Function Get-AADExportPoliciesClaimsMappingPolicy {
    Invoke-Graph 'policies/claimsMappingPolicies'
  }