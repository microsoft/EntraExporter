<# 
 .Synopsis
  Gets the list of languages available for customization associated with a B2B user flow 

 .Description
  GET /identity/b2xUserFlows/{id}/languages
  https://docs.microsoft.com/en-us/graph/api/b2xidentityuserflow-list-languages?view=graph-rest-beta&tabs=http
  
  .Example
  Get-AADExportUserFlowb2xLanguages
#>

Function Get-AADExportUserFlowb2xLanguages {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents
  )
    Invoke-Graph "identity/b2xUserFlows/$(Parents[0])/languages"
  }