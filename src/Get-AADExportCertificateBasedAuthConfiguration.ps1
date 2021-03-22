<# 
 .Synopsis
  Get certificateBasedAuthConfiguration of the tenant

 .Description
  GET /organization
 https://docs.microsoft.com/en-us/graph/api/certificatebasedauthconfiguration-list?view=graph-rest-1.0&tabs=http

 .Example
  Get-AADExportCertificateBasedAuthConfiguration
#>

Function Get-AADExportCertificateBasedAuthConfiguration {
    Invoke-Graph "organization/$($TenantID)/certificateBasedAuthConfiguration"
  }