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
        [ValidateSet('All', 'Config', 'ConditionalAccess', 'Users', 'Groups', 'Applications')]
        [String[]]$Type = 'Config',
        [Parameter(Mandatory = $false)]
        [object]$ExportSchema,
        [Parameter(Mandatory = $false)]
        [string[]]$Parents,
        [switch]
        $All
    )

    if($All) {$Type = @("All")}
    $global:TenantID = (Get-MgContext).TenantId
    $global:Type = $Type

    if (!$ExportSchema) {
        $ExportSchema = @(
            @{
                "Command" = "Get-AADExportApplications"
                "Path" = "Applications"
                "Tag" = @("All", "Applications")
                "Childrens" = @(
                    @{
                        "GraphUri" = "applications/{id}/extensionProperties"
                        "Path" = "ExtensionProperties"
                        "Tag" = @("All", "Applications")
                    },
                    @{
                        "GraphUri" = "applications/{id}/owners"
                        "Select" = "id, userPrincipalName, displayName"
                        "Path" = "Owners"
                        "Tag" = @("All", "Applications")
                    },
                    @{
                        "GraphUri" = "applications/{id}/tokenIssuancePolicies"
                        "Path" = "TokenIssuancePolicies"
                        "Tag" = @("All", "Applications")
                    },
                    @{
                        "GraphUri" = "applications/{id}/tokenLifetimePolicies"
                        "Path" = "TokenLifetimePolicies"
                        "Tag" = @("All", "Applications")
                    }
                )
            },            
            @{
                "Command" = "Get-AADExportUsers"
                "Path" = "Users"
                "Tag" = @("All", "Users")
                "Childrens" = @(
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodFIDO2"
                        "Path" = "Authentication/FIDO2Methods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodMicrosoftAuthenticator"
                        "Path" = "Authentication/MicrosoftAuthenticatorMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodWindowsHelloForBusiness"
                        "Path" = "Authentication/WindowsHelloForBusinessMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodTemporaryAccessPass"
                        "Path" = "Authentication/TemporaryAccessPassMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodPhone"
                        "Path" = "Authentication/PhoneMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodEmail"
                        "Path" = "Authentication/EmailMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "Command" = "Get-AADExportAuthenticationMethodPassword"
                        "Path" = "Authentication/PasswordMethods"
                        "Tag" = @("All", "Users")
                    }
                )
            },
            @{
                "Command" = "Get-AADExportOrganization" 
                "Path" = "Organization.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportGroups" 
                "Path" = "Groups"
                "Tag" = @("All", "Config", "Groups")
                "Childrens" = @(
                    @{
                        "Command" = "Get-AADExportGroupMembers"
                        "Path" = "Members"
                        "Tag" = @("All", "Groups")
                    }
                    @{
                        "Command" = "Get-AADExportGroupOwners"
                        "Path" = "Owners"
                        "Tag" = @("All", "Config", "Groups")
                    }
                )                
            },
            @{
                "Command" = "Get-AADExportGroupSettings"
                "Path" = "GroupSettings.json"
                "Tag" = @("All", "Config")
            },        
            @{
                "Command" = "Get-AADExportSubscribedSkus"
                "Path" = "SubscribedSkus.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportOrganizationBranding"
                "Path" = "OrganizationBranding.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportConditionalAccessPolicies"
                "Path" =  "Identity/Conditional/AccessPolicies"
                "Tag" = @("All", "Config", "ConditionalAccess")
            },
            @{
                "Command" = "Get-AADExportUserFlows"
                "Path" = "Identity/UserFlows.json"
                "Tag" = @("B2C")
            },
            @{
                "Command" = "Get-AADExportDomains"
                "Path" = "Domains.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy"
                "Path" =  "Policies/IdentitySecurityDefaultsEnforcementPolicy.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesAuthorizationPolicy"
                "Path" = "Policies/AuthorizationPolicy.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportIdentityProviders"
                "Path" = "IdentityProviders.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportCertificateBasedAuthConfiguration"
                "Path" = "Policies/CertificateBasedAuthConfiguration.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesActivityBasedTimeoutPolicy"
                "Path" = "Policies/ActivityBasedTimeoutPolicy.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesHomeRealmDiscoveryPolicy"
                "Path" = "Policies/HomeRealmDiscoveryPolicy.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesClaimsMappingPolicy"
                "Path" = "Policies/ClaimsMappingPolicy.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportOrganizationSettings"
                "Path" = "Organization/Settings.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicyEmail"
                "Path" = "Policies/AuthenticationMethod/Email.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicyFIDO2"
                "Path" = "Policies/AuthenticationMethod/FIDO2.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicyMicrosoftAuthenticator"
                "Path" = "Policies/AuthenticationMethod/MicrosoftAuthenticator.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportAuthenticationMethodPolicySMS"
                "Path" = "Policies/AuthenticationMethod/SMS.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" =  "Get-AADExportAuthenticationMethodPolicyTemporaryAccessPass"
                "Path" = "Policies/AuthenticationMethod/TemporaryAccessPass.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesAdminConsentRequestPolicy"
                "Path" = "Policies/AdminConsentRequestPolicy.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportIdentityGovernanceEntitlementManagementSettings"
                "Path" = "IdentityGovernance/EntitlementManagement/Settings.json"
                "Tag" = @("All", "Config")
            }
        )
    }
    $totalExports = $ExportSchema.Count
    $processedItems = 0

    

    foreach ($item in $ExportSchema) {
        $typeMatch = Compare-Object $item.Tag $Type -ExcludeDifferent -IncludeEqual
        if( ($Type -contains 'All' -or $typeMatch)) {
            $outputFileName = Join-Path -Path $Path -ChildPath $item.Path
            $percentComplete = 100 * $processedItems / $totalExports
            Write-Host "Exporting $($item.Path)"
            #Write-Progress -Activity "Reading Azure AD Configuration" -CurrentOperation "Exporting $($item.Path)" -PercentComplete $percentComplete

            $command = Get-ObjectProperty $item 'Command'
            $graphUri = Get-ObjectProperty $item 'GraphUri'

            if($command) {
                if ($Parents){
                    if ($Parents.Count -gt 0) {
                        $command += " -Parents $Parents"
                    }
                }
                $resultItems = Invoke-Expression -Command $command
            }
            else {
                if ($Parents){
                    if ($Parents.Count -gt 0) {
                        $graphUri = $graphUri -replace '{id}', $Parents[0]
                    }
                }                
                $resultItems = Invoke-Graph $graphUri -Select (Get-ObjectProperty $item 'Select')
            }

            if ($outputFileName -match "\.json$") {
                $resultItems | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
            } else {                
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