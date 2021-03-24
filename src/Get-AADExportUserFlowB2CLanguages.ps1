<# 
 .Synopsis
  Gets the list of languages available for customization associated with a B2C user flow 

 .Description
  GET /identity/b2cUserFlows/{id}/languages
  https://docs.microsoft.com/en-us/graph/api/b2cidentityuserflow-list-languages?view=graph-rest-beta&tabs=http
  
  .Example
  Get-AADExportUserFlowB2CLanguages
#>

Function Get-AADExportUserFlowB2CLanguages {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$UserFlowID
  )
    Invoke-Graph "identity/b2cUserFlows/$(UserFlowID[0])/languages"
  }