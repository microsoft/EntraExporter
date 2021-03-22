<# 
 .Synopsis
  Exports the Azure AD Configuration and settings for a tenant
 .Description
  This cmdlet reads the configuration information from the target Azure AD Tenant and produces the output files 
  in a target directory

 .PARAMETER OutputDirectory
    Full path of the directory where the output files will be generated.

.EXAMPLE
   .\Invoke-AADExporter -Path "c:\temp\contoso" 

#>

Function Invoke-AADExporter {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$Path
    )

    $global:TenantID = (Get-MgContext).TenantId

    $itemsToExport = @{

        "Get-AADExportOrganization"         = "Organization.json"
        "Get-AADExportSubscribedSkus"       = "SubscribedSkus.json"
        "Get-AADExportOrganizationBranding"     = "OrganizationBranding.json"
        "Get-AADExportConditionalAccessPolicies"     = "ConditionalAccessPolicies.json"
        "Get-AADExportUserFlows"                     = "UserFlows.json"
    }

    $totalExports = $itemsToExport.Count
    $processedItems = 0

    foreach ($item in $itemsToExport.GetEnumerator()) {
        $functionName = $item.Name
        $outputFileName = Join-Path -Path $Path -ChildPath $item.Value
        $percentComplete = 100 * $processedItems / $totalExports
        Write-Progress -Activity "Reading Azure AD Configuration" -CurrentOperation "Exporting $functionName" -PercentComplete $percentComplete

        Invoke-Expression -Command $functionName | ConvertTo-Json -depth 100 | Out-File $outputFileName

        $processedItems++
    }
}