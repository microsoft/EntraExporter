<# 
 .Synopsis
 Represents a policy to control Azure Active Directory authentication behavior for federated users, in particular for auto-acceleration and user authentication restrictions in federated domains. 

 .Description
  GET /policies/homeRealmDiscoveryPolicies
 https://docs.microsoft.com/en-us/graph/api/resources/homerealmdiscoverypolicy?view=graph-rest-1.0

 .Example
  Get-AADExportPoliciesHomeRealmDiscoveryPolicy
#>

Function Get-AADExportPoliciesHomeRealmDiscoveryPolicy {
    Invoke-Graph 'policies/homeRealmDiscoveryPolicies'
  }