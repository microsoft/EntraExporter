<#
 .Synopsis
  Creates batch requests for accessPackageAssignments

 .Description
  Creates batch requests for GET /identityGovernance/entitlementManagement/accessPackageAssignments
  https://docs.microsoft.com/en-us/graph/api/accesspackageassignment-list?view=graph-rest-beta&tabs=http

 .Example
  Get-AccessPackageAssignments -Parents $parentIds -BasePath "C:\temp\AccessPackages"
#>

Function Get-AccessPackageAssignments {
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory = $true)]
      [string[]]$Parents,

      [Parameter(Mandatory = $true)]
      [string]$BasePath
  )

  foreach ($parentId in $Parents) {
      $outputFileName = Join-Path -Path $BasePath -ChildPath $parentId
      $outputFileName = Join-Path -Path $outputFileName -ChildPath "Assignments"
      $id = $outputFileName -replace '\\', '/'

      # add random number to avoid duplicated ids in batch requests
      $id = _randomizeRequestId $id

      $uri = "identityGovernance/entitlementManagement/accessPackageAssignments?`$filter=(accessPackage/id eq '$parentId')"

      Write-Verbose "Adding request '$uri' with id '$id' to the batch"
      $request = New-GraphBatchRequest -Url $uri -Id $id -header @{ ConsistencyLevel = 'eventual' }

      $BatchRequestBetaApi.Value.Add($request)
  }
}
