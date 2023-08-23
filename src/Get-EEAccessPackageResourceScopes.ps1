<#
 .Synopsis
  Gets the list of businessflowtemplatesRetrieve a list of accessPackage objects.

 .Description
  GET /identityGovernance/entitlementManagement/accessPackages/{id}?$expand=accessPackageResourceRoleScopes($expand=accessPackageResourceRole,accessPackageResourceScope)
  https://docs.microsoft.com/en-us/graph/api/accesspackage-list-accesspackageresourcerolescopes?view=graph-rest-beta&tabs=http

 .Example
  Get-EEAccessPackageResourceScopes
#>

Function Get-EEAccessPackageResourceScopes {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents
  )
    Invoke-Graph "identityGovernance/entitlementManagement/accessPackages/$($Parents[0])" -QueryParameters @{expand='accessPackageResourceRoleScopes(expand=accessPackageResourceRole,accessPackageResourceScope)'} -ApiVersion 'beta'
}
