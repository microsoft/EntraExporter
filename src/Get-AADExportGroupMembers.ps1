<# 
 .Synopsis
  Gets the members of a group 

 .Description
  GET /users
  https://docs.microsoft.com/en-us/graph/api/group-list

 .Example
  Get-AADExportGroupMembers
#>

Function Get-AADExportGroupMembers {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents
  )
  
  Invoke-Graph "groups/$($Parents[0])/members" -Select "id, userPrincipalName, displayName"
}