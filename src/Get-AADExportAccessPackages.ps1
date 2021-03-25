<# 
 .Synopsis
  Gets  a list of accessPackage objects. 

 .Description
  GET /identityGovernance/entitlementManagement/accessPackages
  https://docs.microsoft.com/en-us/graph/api/resources/accesspackage?view=graph-rest-beta 

 .Example
  Get-AADExportaccessPackages
#>

Function Get-AADExportAccessPackages {
    Invoke-Graph 'identityGovernance/entitlementManagement/accessPackages'
}