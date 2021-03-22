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
        [String]$Path,
        [Parameter(Mandatory = $false)]
        [object]$ExportSchema
    )

    $global:TenantID = (Get-MgContext).TenantId

    if (!$ExportSchema) {
        $ExportSchema = @(
            @{
                "Command" = "Get-AADExportUsers"
                "Path" = "Users"
                "Childrens" = @(
                    @{
                        "Command" = "Get-AADExportUserAuthenticationMethodFIDO2"
                        "Path" = "Authentication/FIDO2Methods"
                    }
                )
            },
            @{
                "Command" = "Get-AADExportOrganization" 
                "Path" = "Organization.json"
            },
            @{
                "Command" = "Get-AADExportSubscribedSkus"
                "Path" = "SubscribedSkus.json"
            },
            @{
                "Command" = "Get-AADExportOrganizationBranding"
                "Path" = "OrganizationBranding.json"
            },
            @{
                "Command" = "Get-AADExportConditionalAccessPolicies" 
                "Path" =  "Identity/Conditional/AccessPolicies.json"
            },
            #@{ ## 0817c655-a853-4d8f-9723-3a333b5b9235' is not an Azure AD B2C directory. Access to this Api can only be made for an Azure AD B2C directory.
            #    "Command" = "Get-AADExportUserFlows"
            #    "Path" = "Identity/UserFlows.json"
            #},
            @{
                "Command" = "Get-AADExportDomains"
                "Path" = "Domains.json"
            },
            @{
                "Command" = "Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy"
                "Path" =  "Policies/IdentitySecurityDefaultsEnforcementPolicy.json"
            },
            @{
                "Command" = "Get-AADExportPoliciesAuthorizationPolicy"
                "Path" = "Policies/AuthorizationPolicy.json"
            },
            @{
                "Command" = "Get-AADExportIdentityProviders"
                "Path" = "IdentityProviders.json"
            },
            @{
                "Command" = "Get-AADExportCertificateBasedAuthConfiguration"
                "Path" = "Policies/CertificateBasedAuthConfiguration.json"
            },
            @{
                "Command" = "Get-AADExportCertificateBasedAuthConfiguration"
                "Path" = "Policies/CertificateBasedAuthConfiguration.json"
            },
            @{
                "Command" = "Get-AADExportOrganizationSettings"
                "Path" = "Organization/Settings.json"
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicyEmail"
                "Path" = "Policies/AuthenticationMethod/Email.json"
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicyFIDO2"
                "Path" = "Policies/AuthenticationMethod/FIDO2.json"
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicyMicrosoftAuthenticator"
                "Path" = "Policies/AuthenticationMethod/MicrosoftAuthenticator.json"
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicySMS"
                "Path" = "Policies/AuthenticationMethod/SMS.json"
            },
            @{
                "Command" =  "Get-AADExportAuthenticationMethodPolicyTemporaryAccessPass"
                "Path" = "Policies/AuthenticationMethod/TemporaryAccessPass.json"
            },
            @{
                "Command" = "Get-AADExportPoliciesAdminConsentRequestPolicy"
                "Path" = "Policies/AdminConsentRequestPolicy.json"
            },
            @{
                "Command" = "Get-AADExportIdentityGovernanceEntitlementManagementSettings"
                "Path" = "IdentityGovernance/EntitlementManagement/Settings.json"
            }
        )
    }
    $totalExports = $ExportSchema.Count
    $processedItems = 0

    foreach ($item in $ExportSchema) {
        $outputFileName = Join-Path -Path $Path -ChildPath $item.Path
        $percentComplete = 100 * $processedItems / $totalExports
        Write-Progress -Activity "Reading Azure AD Configuration" -CurrentOperation "Exporting $($item.Path)" -PercentComplete $percentComplete

        if ($outputFileName -match "\.json$") {
            Invoke-Expression -Command $item.Command | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
        } else {
            $resultItems = Invoke-Expression -Command $item.Command
            foreach($resultItem in $resultItems) {
                $itemOutputFileName = Join-Path -Path $outputFileName -ChildPath "$($resultItem.id).json"
                $item | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $itemOutputFileName -Force)
            }
        }
        $processedItems++
    }
}