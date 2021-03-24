<# 
 .Synopsis
  Gets the list of businessflowtemplates

 .Description
  GET /users
  https://docs.microsoft.com/en-us/graph/api/businessflowtemplate-list?view=graph-rest-beta&tabs=http 

 .Example
  AADExportBusinessFlowTemplates
#>

Function Get-AADExportBusinessFlowTemplates {
    Invoke-Graph 'businessFlowTemplates'
}