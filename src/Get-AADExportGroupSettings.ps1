<# 
 .Synopsis
  Gets the tenant-wide group settings

 .Description
  GET /groupSettings
  https://docs.microsoft.com/en-us/graph/api/groupsetting-list

 .Example
  Get-AADExportGroupSettings
#>

Function Get-AADExportGroupSettings {
  Invoke-Graph 'groupSettings' -ApiVersion 'v1.0'
}