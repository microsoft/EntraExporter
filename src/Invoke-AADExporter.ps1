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
        "Get-AADExportConditionalAccessPolicies"     = "Identity/Conditional/AccessPolicies.json"
        #"Get-AADExportUserFlows"                     = "Identity/UserFlows.json" ## 0817c655-a853-4d8f-9723-3a333b5b9235' is not an Azure AD B2C directory. Access to this Api can only be made for an Azure AD B2C directory.
        "Get-AADExportDomains"              = "Domains.json"
        "Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy" = "Policies/IdentitySecurityDefaultsEnforcementPolicy.json"
        "Get-AADExportPoliciesAuthorizationPolicy" = "Policies/AuthorizationPolicy.json"
        "Get-AADExportIdentityProviders" = "IdentityProviders.json"
        "Get-AADExportCertificateBasedAuthConfiguration" ="Policies/CertificateBasedAuthConfiguration.json"
        "Get-AADExportOrganizationSettings" = "Organization/Settings.json"
        "Get-AADExportAuthenticationMethodPolicyEmail" = "AuthenticationMethodPolicy/Email.json"
        "Get-AADExportAuthenticationMethodPolicyFIDO2" = "AuthenticationMethodPolicy/FIDO2.json"
        "Get-AADExportAuthenticationMethodPolicyMicrosoftAuthenticator" = "AuthenticationMethodPolicy/MicrosoftAuthenticator.json"
        "Get-AADExportAuthenticationMethodPolicySMS" = "AuthenticationMethodPolicy/SMS.json"
        "Get-AADExportAuthenticationMethodPolicyTemporaryAccessPass" = "AuthenticationMethodPolicy/TemporaryAccessPass.json"
    }

    $totalExports = $itemsToExport.Count
    $processedItems = 0

    foreach ($item in $itemsToExport.GetEnumerator()) {
        $functionName = $item.Name
        $filePath = $item.Value
        $outputFileName = Join-Path -Path $Path -ChildPath $filePath
        $percentComplete = 100 * $processedItems / $totalExports
        Write-Progress -Activity "Reading Azure AD Configuration" -CurrentOperation "Exporting $filePath" -PercentComplete $percentComplete

        if ($outputFileName -match "\.json$") {
            Invoke-Expression -Command $functionName | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
        } else {
            $items = Invoke-Expression -Command $functionName
            foreach($item in $items) {
                $itemOutputFileName = Join-Path -Path $outputFileName -ChildPath "$($item.id).json"
                $item | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $itemOutputFileName -Force)
            }
        }

        $processedItems++
    }
}