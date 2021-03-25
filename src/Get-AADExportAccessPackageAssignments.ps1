<# 
 .Synopsis
  Gets the list of accessPackageAssignments 

 .Description
  GET /identityGovernance/entitlementManagement/accessPackageAssignments?$filter=accessPackage/id eq 
  https://docs.microsoft.com/en-us/graph/api/accesspackageassignment-list?view=graph-rest-beta&tabs=http 

 .Example
  Get-AADExportAccessPackagesAssignments
#>

Function Get-AADExportAccessPackageAssignments {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents
  )
    Invoke-Graph 'identityGovernance/entitlementManagement/accessPackageAssignments' -Filter "(accessPackage/id eq '$($Parents[0])')"  
}