<# 
 .Synopsis
  Gets the owners of a group 

 .Description
  GET /users
  https://docs.microsoft.com/en-us/graph/api/group-list

 .Example
  Get-AADExportGroupOwners
#>

Function Get-AADExportGroupOwners {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents
  )
  
  Invoke-Graph "groups/$($Parents[0])/owners" -Select "id, userPrincipalName, displayName"
}