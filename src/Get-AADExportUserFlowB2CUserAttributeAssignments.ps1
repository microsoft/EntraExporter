<# 
 .Synopsis
  Gets the userflows Attribute Assignments associated with a B2C user flow 

 .Description
  GET /identity/b2cUserFlows/{id}/userAttributeAssignments??$expand=userAttribute
  https://docs.microsoft.com/en-us/graph/api/b2cidentityuserflow-list-userattributeassignments?view=graph-rest-beta&tabs=http

  .Example
  Get-AADExportUserFlowB2CUserAttributeAssignments
#>

Function Get-AADExportUserFlowB2CUserAttributeAssignments{
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents
  )
    Invoke-Graph "identity/b2cUserFlows/$(Parents[0])/userAttributeAssignments??$expand=userAttribute"
  }