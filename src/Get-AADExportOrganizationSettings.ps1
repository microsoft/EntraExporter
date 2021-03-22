<# 
 .Synopsis
  Get the properties and relationships of the currently authenticated organization. 

 .Description
  GET /organization/settings
  https://docs.microsoft.com/en-us/graph/api/organizationsettings-get

 .Example
  Get-AADExportOrganizationSettings
#>

Function Get-AADExportOrganizationSettings {
  Invoke-Graph "organization/$($TenantID)/settings"
}