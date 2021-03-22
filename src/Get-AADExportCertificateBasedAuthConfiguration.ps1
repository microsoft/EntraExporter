<# 
 .Synopsis
  Get the properties and relationships of the currently authenticated organization. 

 .Description
  GET /organization
 https://docs.microsoft.com/en-us/graph/api/certificatebasedauthconfiguration-list?view=graph-rest-1.0&tabs=http

 .Example
  Get-AADExportCertificateBasedAuthConfiguration
#>

Function Get-AADExportCertificateBasedAuthConfiguration {
    Invoke-Graph "organization/$($TenantID)/certificateBasedAuthConfiguration"
  }