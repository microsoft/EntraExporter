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
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]$Path,        
        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Config', 'Users')]
        [String[]]$Type = 'Config',
        [Parameter(Mandatory = $false)]
        [object]$ExportSchema,
        [Parameter(Mandatory = $false)]
        [string[]]$Parents,
        [switch]
        $All
    )

    $global:TenantID = (Get-MgContext).TenantId

    if (!$ExportSchema) {
        $ExportSchema = @(
            @{
                "Command" = "Get-AADExportUsers"
                "Path" = "Users"
                "Tag" = @("Users")
                "Childrens" = @(
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodFIDO2"
                        "Path" = "Authentication/FIDO2Methods"
                        "Tag" = @("Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodMicrosoftAuthenticator"
                        "Path" = "Authentication/MicrosoftAuthenticatorMethods"
                        "Tag" = @("Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodWindowsHelloForBusiness"
                        "Path" = "Authentication/WindowsHelloForBusinessMethods"
                        "Tag" = @("Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodTemporaryAccessPass"
                        "Path" = "Authentication/TemporaryAccessPassMethods"
                        "Tag" = @("Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodPhone"
                        "Path" = "Authentication/PhoneMethods"
                        "Tag" = @("Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodEmail"
                        "Path" = "Authentication/EmailMethods"
                        "Tag" = @("Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodPassword"
                        "Path" = "Authentication/PasswordMethods"
                        "Tag" = @("Users")
                    }
                )
            },
            @{
                "Command" = "Get-AADExportOrganization" 
                "Path" = "Organization.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportSubscribedSkus"
                "Path" = "SubscribedSkus.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportOrganizationBranding"
                "Path" = "OrganizationBranding.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportConditionalAccessPolicies" 
                "Path" =  "Identity/Conditional/AccessPolicies.json"
                "Tag" = @("Config")
            },
            #@{ ## 0817c655-a853-4d8f-9723-3a333b5b9235' is not an Azure AD B2C directory. Access to this Api can only be made for an Azure AD B2C directory.
            #    "Command" = "Get-AADExportUserFlows"
            #    "Path" = "Identity/UserFlows.json"
            #},
            @{
                "Command" = "Get-AADExportDomains"
                "Path" = "Domains.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy"
                "Path" =  "Policies/IdentitySecurityDefaultsEnforcementPolicy.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesAuthorizationPolicy"
                "Path" = "Policies/AuthorizationPolicy.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportIdentityProviders"
                "Path" = "IdentityProviders.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportCertificateBasedAuthConfiguration"
                "Path" = "Policies/CertificateBasedAuthConfiguration.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportCertificateBasedAuthConfiguration"
                "Path" = "Policies/CertificateBasedAuthConfiguration.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportOrganizationSettings"
                "Path" = "Organization/Settings.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicyEmail"
                "Path" = "Policies/AuthenticationMethod/Email.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicyFIDO2"
                "Path" = "Policies/AuthenticationMethod/FIDO2.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicyMicrosoftAuthenticator"
                "Path" = "Policies/AuthenticationMethod/MicrosoftAuthenticator.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicySMS"
                "Path" = "Policies/AuthenticationMethod/SMS.json"
                "Tag" = @("Config")
            },
            @{
                "Command" =  "Get-AADExportAuthenticationMethodPolicyTemporaryAccessPass"
                "Path" = "Policies/AuthenticationMethod/TemporaryAccessPass.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesAdminConsentRequestPolicy"
                "Path" = "Policies/AdminConsentRequestPolicy.json"
                "Tag" = @("Config")
            },
            @{
                "Command" = "Get-AADExportIdentityGovernanceEntitlementManagementSettings"
                "Path" = "IdentityGovernance/EntitlementManagement/Settings.json"
                "Tag" = @("Config")
            }
        )
    }
    $totalExports = $ExportSchema.Count
    $processedItems = 0

    if($All) {$Type = @("All")}

    foreach ($item in $ExportSchema) {
        $typeMatch = Compare-Object $item.Tag $Type -ExcludeDifferent
        if($Type -contains 'All' -or $typeMatch) {
            $outputFileName = Join-Path -Path $Path -ChildPath $item.Path
            $percentComplete = 100 * $processedItems / $totalExports
            Write-Progress -Activity "Reading Azure AD Configuration" -CurrentOperation "Exporting $($item.Path)" -PercentComplete $percentComplete

            $command = $item.Command
            if ($Parents){
                if ($Parents.Count -gt 0) {
                    $command += " -Parents $Parents"
                }
            }

            if ($outputFileName -match "\.json$") {
                Invoke-Expression -Command $command | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
            } else {
                $resultItems = Invoke-Expression -Command $command
                foreach($resultItem in $resultItems) {
                    if (!$resultItem.ContainsKey('id')) {
                        continue
                    }
                    $itemOutputFileName = Join-Path -Path $outputFileName -ChildPath $resultItem.id
                    $resultItem | ConvertTo-Json -depth 100 | Out-File (New-Item -Path "$($itemOutputFileName).json" -Force)
                    if ($item.ContainsKey("Childrens")) {
                        $itemParents = $Parents
                        $itemParents += $resultItem.Id
                        Invoke-AADExporter -Path $itemOutputFileName -Type $Type -ExportSchema $item.Childrens -Parents $itemParents
                    }
                }
            }
        }

        $processedItems++
    }
}