<# 
 .Synopsis
  Gets the list of access reviews via businessFlowTemplaytes

 .Description
  GET /accessReviews?$filter=businessFlowTemplateId eq {businessFlowTemplate-id}&$top={pagesize}&$skip=0
  https://docs.microsoft.com/en-us/graph/api/accessreview-list?view=graph-rest-beta&tabs=http#code-try-1

 .Example
  Get-AADExportAccessReviews
#>

Function Get-AADExportAccessReviews {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents
  )
  
  Invoke-Graph  'accessReviews' -Filter "(businessFlowTemplateId eq '$($Parents[0])')" -ApiVersion 'beta'
}