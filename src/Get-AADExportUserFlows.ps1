<# 
 .Synopsis
  Gets the userflows associated with the Active Directory. 

 .Description
  GET /identity/userFlows
  https://graph.microsoft.com/beta/identity/userFlows

 .Example
  Get-AADExportUserFlows
#>

Function Get-AADExportUserFlows {
    Invoke-Graph 'identity/userFlows'
  }