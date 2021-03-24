<# 
 .Synopsis
  Retrieve a list of connectedOrganization objects. 

 .Description
  GET /organization
  https://docs.microsoft.com/en-us/graph/api/connectedorganization-list?view=graph-rest-beta&tabs=http

 .Example
  Get-AADExportConnectedOrganizations
#>

Function Get-AADExportConnectedOrganizations {
  Invoke-Graph 'identityGovernance/entitlementManagement/connectedOrganizations'
}