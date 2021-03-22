<# 
 .Synopsis
  Gets the users 

 .Description
  GET /users
  https://docs.microsoft.com/en-us/graph/api/user-list

 .Example
  Get-AADExportUsers
#>

Function Get-AADExportUsers {
    Invoke-Graph 'users'
}