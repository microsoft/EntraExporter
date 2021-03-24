<# 
 .Synopsis
  Gets the B2X userflows associated with the Active Directory. 

 .Description
  GET /identity/b2xUserFlows
 https://docs.microsoft.com/en-us/graph/api/identitycontainer-list-b2xuserflows?view=graph-rest-beta&tabs=http

 .Example
  Get-AADExportB2XUserFlows
#>

Function Get-AADExportB2XUserFlows {
    Invoke-Graph 'identity/b2xuserFlows?$expand=identityProviders'
  }