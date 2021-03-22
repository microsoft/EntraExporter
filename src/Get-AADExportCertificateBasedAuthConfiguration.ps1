<# 
 .Synopsis
  Get certificateBasedAuthConfiguration of the tenant

 .Description
  GET /organization
 https://docs.microsoft.com/en-us/graph/api/certificatebasedauthconfiguration-list

 .Example
  Get-AADExportCertificateBasedAuthConfiguration
#>

Function Get-AADExportCertificateBasedAuthConfiguration {  
    Invoke-Graph "organization/$($TenantID)/certificateBasedAuthConfiguration"
  }