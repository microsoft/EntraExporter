<# 
 .Synopsis
  Get the properties and relationships of the currently authenticated organization. 

 .Description
  GET /organization
  https://docs.microsoft.com/en-us/graph/api/organization-get

 .Example
  Get-AADExportOrganizationBranding
#>

Function Get-AADExportOrganizationBranding {
  Invoke-Graph "/organization/$($TenantID)/branding/localizations"
}