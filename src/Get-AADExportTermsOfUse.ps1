<# 
 .Synopsis
  Represents a tenant's customizable terms of use agreement that is created and managed with Azure Active Directory (Azure AD).

 .Description
  GET /organization
  https://docs.microsoft.com/en-us/graph/api/agreement-list?view=graph-rest-beta&tabs=http

 .Example
  Get-AADExportTermsOfUse
#>

Function Get-AADExportTermsOfUse {
  Invoke-Graph 'identityGovernance/termsOfUse/agreements'
}