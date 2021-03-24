<# 
 .Synopsis
  Gets the userflows Attribute Assignments associated with a B2B user flow 

 .Description
  GET /identity/b2xUserFlows/{id}/userAttributeAssignments??$expand=userAttribute
  https://docs.microsoft.com/en-us/graph/api/b2xidentityuserflow-list-userattributeassignments?view=graph-rest-beta&tabs=http

  .Example
  Get-AADExportUserFlowb2xUserAttributeAssignments
#>

Function Get-AADExportUserFlowb2xUserAttributeAssignments {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents
  )
    Invoke-Graph "identity/b2xUserFlows/$(Parents[0])/userAttributeAssignments??$expand=userAttribute"
  }