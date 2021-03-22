<# 
 .Synopsis
  Get the tenant Branding
  #to do : some of the binary properties are missing

 .Description
  https://docs.microsoft.com/en-us/graph/api/resources/organizationalbrandingproperties?view=graph-rest-1.0

 .Example
  Get-AADExportOrganizationBranding
#>

Function Get-AADExportOrganizationBranding {
  Invoke-Graph "organization/$($TenantID)/branding/localizations"
}