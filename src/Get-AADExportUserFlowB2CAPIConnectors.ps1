<# 
 .Synopsis
  Gets the list of api connectors associated with a B2C user flow 

 .Description
  GET /identity/b2cUserFlows/{id}/apiConnectorConfiguration
  https://docs.microsoft.com/en-us/graph/api/b2cidentityuserflow-get-apiconnectorconfiguration?view=graph-rest-beta&tabs=http
  
  .Example
  Get-AADExportUserFlowB2CAPIConnectors
#>

Function Get-AADExportUserFlowB2CAPIConnectors {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$UserFlowID
  )
    Invoke-Graph "identity/b2cUserFlows/$(UserFlowID[0])/apiConnectorConfiguration"
  }