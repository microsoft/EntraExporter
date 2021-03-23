<# 
 .Synopsis
  Gets the API connectors associated with the Active Directory. 

 .Description
  GET /identity/apiConnectors
  https://docs.microsoft.com/en-us/graph/api/identityapiconnector-list?view=graph-rest-beta&tabs=http
 
  .Example
  Get-AADExportAPIConnectors
#>

Function Get-AADExportAPIConnectors {
    Invoke-Graph 'identity/apiConnectors'
  }