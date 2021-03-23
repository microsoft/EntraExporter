<# 
 .Synopsis
  Gets the groups 

 .Description
  GET /users
  https://docs.microsoft.com/en-us/graph/api/group-list

 .Example
  Get-AADExportGroups
#>

Function Get-AADExportGroups {
  if((Compare-Object $Type @('Config') -ExcludeDifferent)){
    Invoke-Graph 'groups' -Filter "groupTypes/any(c:c eq 'DynamicMembership')"
  }
  else {
    Invoke-Graph 'groups'
  }
}