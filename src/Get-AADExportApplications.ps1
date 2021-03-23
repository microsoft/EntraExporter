<# 
 .Synopsis
  Represents an application. Any application that outsources authentication to Azure Active Directory (Azure AD) must be registered in a directory. 

 .Description
  GET /applications
  https://docs.microsoft.com/en-us/graph/api/domain-list

 .Example
  Get-AADExportApplications
#>

Function Get-AADExportApplications {
  Invoke-Graph 'applications'
}