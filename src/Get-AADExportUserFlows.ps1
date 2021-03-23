<# 
 .Synopsis
  Gets the userflows associated with the Active Directory. 

 .Description
  GET /identity/userFlows
  https://docs.microsoft.com/en-us/graph/api/identityuserflow-list?view=graph-rest-beta&tabs=http

 .Example
  Get-AADExportUserFlows
#>

Function Get-AADExportUserFlows {
    Invoke-Graph 'identity/userFlows'
  }