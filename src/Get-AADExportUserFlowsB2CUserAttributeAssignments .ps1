<# 
 .Synopsis
  Gets the userflows Attribute Assignments associated with a B2C user flow 

 .Description
  GET /identity/b2cUserFlows/{id}/userAttributeAssignments?
  https://docs.microsoft.com/en-us/graph/api/b2cidentityuserflow-list-userattributeassignments?view=graph-rest-beta&tabs=http

  .Example
  Get-AADExportUserFlowsB2CUserAttributeAssignments
#>

Function Get-AADExportUserFlowsB2CUserAttributeAssignments {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$UserFlowID
  )
    Invoke-Graph "identity/b2cUserFlows/$(UserFlowID[0])/userAttributeAssignments?"
  }