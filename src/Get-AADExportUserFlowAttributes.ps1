<# 
 .Synopsis
  Gets the userflows associated with the Active Directory. 

 .Description
  GET /identity/userFlowAttributes
  https://docs.microsoft.com/en-us/graph/api/identityuserflowattribute-list?view=graph-rest-beta&tabs=http

 .Example
  Get-AADExportUserFlowAttributes
#>

Function Get-AADExportUserFlowAttributes {
    Invoke-Graph 'identity/userFlowAttributes'
  }