<# 
 .Synopsis
  Retrieve a list of domain objects. 

 .Description
  GET /domains
  https://docs.microsoft.com/en-us/graph/api/domain-list

 .Example
  Get-AADExportDomains
#>

Function Get-AADExportDomains {
  Invoke-Graph 'domains'
}