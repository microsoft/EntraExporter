<#
 .Synopsis
  Gets the list of accessPackageAssignmentPolicies

 .Description
  GET /identityGovernance/entitlementManagement/accessPackageAssignmentPolicies
  https://docs.microsoft.com/en-us/graph/api/accesspackageassignmentpolicy-list?view=graph-rest-beta&tabs=http

 .Example
  EEAccessPackagesAssignmentPolicies
#>

Function Get-EEAccessPackageAssignmentPolicies  {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents
  )
  Invoke-Graph 'identityGovernance/entitlementManagement/accessPackageAssignmentPolicies' -Filter "(accessPackage/id eq '$($Parents[0])')"  -ApiVersion 'beta'
}
