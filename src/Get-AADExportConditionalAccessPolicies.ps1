<# 
 .Synopsis
  Gets the Conditional Access Policies associated with the AAD organization. 

 .Description
  GET /identity/conditionalAccess/policies
  https://docs.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy

 .Example
  Get-AADExportConditionalAccessPolicies
#>

Function Get-AADExportConditionalAccessPolicies {
    Invoke-Graph 'identity/conditionalAccess/policies'
  }