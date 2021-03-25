<# 
 .Synopsis
  Gets all the userflows associated with the Active Directory B2C Tenant along with the Identity
  Providers

 .Description
  GET /identity/b2cUserFlows?$expand=identityProviders
  https://docs.microsoft.com/en-us/graph/api/identitycontainer-list-b2cuserflows?view=graph-rest-beta&tabs=http
 
  .Example
  Get-AADExportUserFlowsB2C
#>

Function Get-AADExportUserFlowsB2C {
    Invoke-Graph 'identity/b2cUserFlows?$expand=identityProviders'
  }