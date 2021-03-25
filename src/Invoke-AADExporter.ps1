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
        [ValidateSet('All', 'Config', 'ConditionalAccess', 'Users', 'Groups', 'Applications', 'ServicePrincipals','B2C','B2B',"PIM")]
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
                "Command" = "Get-AADExportAccessPackages"
                "Path" = "IdentityGovernance\EntitlementManagement\AccessPackages"
                "Tag" = @("All", "Config")
                "Childrens" = @(
                    @{
                        "Command" = "Get-AADExportAccessPackageAssignmentPolicies"
                        "Path" = "AssignmentPolicies"
                        "Tag" = @("All", "Config")
                    },
                    @{
                        "Command" = "Get-AADExportAccessPackageAssignments"
                        "Path" = "Assignments"
                        "Tag" = @("All", "Config")
                    },
                    @{
                        "Command" = "Get-AADExportAccessPackageResourceScopes"
                        "Path" = "ResourceScopes"
                        "Tag" = @("All", "Config")
                    }
                )
            },
            @{
                "Command" = "Get-AADExportBusinessFlowTemplates"
                "Path" = "IdentityGovernance/AccessReviews"
                "Tag" = @("All","Config")
                "Childrens" = @(
                    @{
                        "Command" = "Get-AADExportAccessReviews"
                        "Path" = ""
                        "Tag" = @("All", "Config")
                        "Childrens" = @(
                            @{
                                "GraphUri" = "accessReviews/{id}/reviewers"
                                "Path" = "Reviewers"
                                "Tag" = @("All", "Config")  
                            }
                        )}
                )
            },
            @{
                "Command" = "Get-AADExportTermsOfUse"
                "Path" = "IdentityGovernance/TermsOfUse"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportConnectedOrganizations"
                "Path" = "IdentityGovernance/EntitlementManagement/ConnectedOrganizations"
                "Tag" = @("All", "Config")
                "Childrens" = @(
                    @{
                        "GraphUri" = "identityGovernance/entitlementManagement/connectedOrganizations/{id}/externalSponsors"
                        "Path" = "ExternalSponsors"
                        "Tag" = @("All", "Config")
                    },
                    @{
                        "GraphUri" = "identityGovernance/entitlementManagement/connectedOrganizations/{id}/internalSponsors"
                        "Path" = "InternalSponsors"
                        "Tag" = @("All", "Config")
                    }
                )    
            },
            @{
                "GraphUri" = "servicePrincipals"
                "Path" = "ServicePrincipals"
                "Tag" = @("All", "ServicePrincipals")
                "Childrens" = @(
                    @{
                        "GraphUri" = "servicePrincipals/{id}/appRoleAssignments"
                        "Path" = "AppRoleAssignments"
                        "Tag" = @("All", "ServicePrincipals")
                    },
                    @{
                        "GraphUri" = "servicePrincipals/{id}/oauth2PermissionGrants"
                        "Path" = "Oauth2PermissionGrants"
                        "Tag" = @("All", "ServicePrincipals")
                    },
                    @{
                        "GraphUri" = "servicePrincipals/{id}/delegatedPermissionClassifications"
                        "Path" = "DelegatedPermissionClassifications"
                        "Tag" = @("All", "ServicePrincipals")
                    },
                    @{
                        "GraphUri" = "servicePrincipals/{id}/owners"
                        "Select" = "id, userPrincipalName, displayName"
                        "Path" = "Owners"
                        "Tag" = @("All", "ServicePrincipals")
                    },
                    @{
                        "GraphUri" = "servicePrincipals/{id}/claimsMappingPolicies"
                        "Path" = "claimsMappingPolicies"
                        "Tag" = @("All", "ServicePrincipals")
                    },
                    @{
                        "GraphUri" = "servicePrincipals/{id}/homeRealmDiscoveryPolicies"
                        "Path" = "homeRealmDiscoveryPolicies"
                        "Tag" = @("All", "ServicePrincipals")
                    },
                    @{
                        "GraphUri" = "servicePrincipals/{id}/tokenIssuancePolicies"
                        "Path" = "tokenIssuancePolicies"
                        "Tag" = @("All", "ServicePrincipals")
                    },
                    @{
                        "GraphUri" = "servicePrincipals/{id}/tokenLifetimePolicies"
                        "Path" = "tokenLifetimePolicies"
                        "Tag" = @("All", "ServicePrincipals")
                    }
                )
            },            
            @{
                "Command" = "Get-AADExportUsers"
                "Path" = "Users"
                "Tag" = @("All", "Users")
                "Childrens" = @(
                    @{
                        "GraphUri" = "users/{id}/authentication/fido2Methods"
                        "Path" = "Authentication/FIDO2Methods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "GraphUri" = "users/{id}/authentication/microsoftAuthenticatorMethods"
                        "Path" = "Authentication/MicrosoftAuthenticatorMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "GraphUri" = "users/{id}/authentication/windowsHelloForBusinessMethods"
                        "Path" = "Authentication/WindowsHelloForBusinessMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "GraphUri" = "users/{id}/authentication/temporaryAccessPassMethods"
                        "Path" = "Authentication/TemporaryAccessPassMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "GraphUri" = "users/{id}/authentication/phoneMethods"
                        "Path" = "Authentication/PhoneMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "GraphUri" = "users/{id}/authentication/emailMethods"
                        "Path" = "Authentication/EmailMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "GraphUri" = "users/{id}/authentication/passwordMethods"
                        "Path" = "Authentication/PasswordMethods"
                        "Tag" = @("All", "Users")
                    },
                    @{
                        "GraphUri" = "users/{id}/extensions"
                        "Path" = "Extensions"
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
                    },
                    @{
                        "GraphUri" = "groups/{id}/extensions"
                        "Path" = "Extensions"
                        "Tag" = @("All", "Groups")
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
                "GraphUri" = "directoryRoles"
                "Path" = "DirectoryRoles"
                "Tag" = @("All", "Config")
                "Childrens" = @(
                    @{
                        "GraphUri" = "directoryRoles/{id}/members"
                        "Select" = "id, userPrincipalName, displayName"
                        "Path" = "Members"
                        "Tag" = @("All", "Config")
                    }
                    @{
                        "GraphUri" = "directoryroles/{id}/scopedMembers"
                        "Path" = "ScopedMembers"
                        "Tag" = @("All", "Config")
                    }
                )
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
                "GraphUri" = "identity/conditionalAccess/namedLocations"
                "Path" =  "Identity/Conditional/NamedLocations"
                "Tag" = @("All", "Config", "ConditionalAccess")
            },
            @{
                "Command" = "Get-AADExportUserFlows"
                "Path" = "Identity/UserFlows.json"
                "Tag" = @("B2C")
            },
            @{
                "Command" = "Get-AADExportUserFlowsB2C"
                "Path" = "Identity/B2CUserFlows.json"
                "Tag" = @("B2C")
            },
            @{
                "Command" = "Get-AADExportUserFlowAttributes"
                "Path" = "Identity/UserFlowAttributes.json"
                "Tag" = @("B2C")
            },
            @{
                "GraphUri" = "identity/b2cUserFlows"
                "Path" = "B2C/UserFlows"
                "Tag" = @("B2C")
                "Childrens" = @(
                    @{
                        "GraphUri" = "identity/b2cUserFlows/{id}/identityProviders"
                        "Path" = "IdentityProviders"
                        "Tag" = @("B2C")
                    },
                    @{
                        "GraphUri" = "identity/b2cUserFlows/{id}/userAttributeAssignments"
                        "QueryParameters" = @{ expand = 'userAttribute' }
                        "Path" = "AttributeAssignments"
                        "Tag" = @("B2C")
                    },
                    @{
                        "GraphUri" = "identity/b2cUserFlows/{id}/apiConnectorConfiguration"
                        "QueryParameters" = @{ expand = 'postFederationSignup,postAttributeCollection' }
                        "Path" = "APIConnectors"
                        "Tag" = @("B2C")
                    },
                    @{
                        "GraphUri" = "identity/b2cUserFlows/{id}/languages"
                        "Path" = "Languages"
                        "Tag" = @("B2C")
                    }
                )
            },
            @{
                "GraphUri" = "identity/b2xUserFlows"
                "Path" = "B2B/UserFlows"
                "Tag" = @("All","B2B")
                "Childrens" = @(
                    @{
                        "GraphUri" = "identity/b2xUserFlows/{id}/identityProviders"
                        "Path" = "IdentityProviders"
                        "Tag" = @("All","B2B")
                    },
                    @{
                        "GraphUri" = "identity/b2xUserFlows/{id}/userAttributeAssignments"
                        "QueryParameters" = @{ expand = 'userAttribute' }
                        "Path" = "AttributeAssignments"
                        "Tag" = @("All","B2B")
                    },
                    @{
                        "GraphUri" = "identity/b2xUserFlows/{id}/apiConnectorConfiguration"
                        "QueryParameters" = @{ expand = 'postFederationSignup,postAttributeCollection' }
                        "Path" = "APIConnectors"
                        "Tag" = @("All","B2B")
                    },
                    @{
                        "GraphUri" = "identity/b2xUserFlows/{id}/languages"
                        "Path" = "Languages"
                        "Tag" = @("All","B2B")
                    }
                )
            },
            @{
                "Command" = "Get-AADExportAPIConnectors"
                "Path" = "Identity/APIConnectors.json"
                "Tag" = @("All")
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
                "GraphUri" = "policies/featureRolloutPolicies"
                "Path" = "Policies/FeatureRolloutPolicies"
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
                "Command" = "Get-AADExportPoliciesTokenIssuancePolicy"
                "Path" = "Policies/TokenIssuancePolicy.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportPoliciesTokenLifetimePolicy"
                "Path" = "Policies/TokenLifetimePolicy.json"
                "Tag" = @("All", "Config")
            },
            @{
                "Command" = "Get-AADExportOrganizationSettings"
                "Path" = "Organization/Settings.json"
                "Tag" = @("All", "Config")
            },
            @{
                "GraphUri" = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/email"
                "Path" = "Policies/AuthenticationMethod/Email.json"
                "Tag" = @("All", "Config")
            },
            @{
                "GraphUri" = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2"
                "Path" = "Policies/AuthenticationMethod/FIDO2.json"
                "Tag" = @("All", "Config")
            },
            @{
                "GraphUri" = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator"
                "Path" = "Policies/AuthenticationMethod/MicrosoftAuthenticator.json"
                "Tag" = @("All", "Config")
            },
            @{
                "GraphUri" = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms"
                "Path" = "Policies/AuthenticationMethod/SMS.json"
                "Tag" = @("All", "Config")
            },
            @{
                "GraphUri" = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass"
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
            },
            @{
                "GraphUri" = "AdministrativeUnits"
                "Path" = "AdministrativeUnits"
                "Tag" = @("All", "Config")
                "Childrens" = @(
                    @{
                        "GraphUri" = "administrativeUnits/{id}/members"
                        "Path" = "Members"
                        "Select" = "Id"
                        "Tag" = @("All", "Config")
                    },
                    @{
                        "GraphUri" = "administrativeUnits/{id}/scopedRoleMembers"
                        "Path" = "ScopedRoleMembers"
                        "Tag" = @("All", "Config")
                    },
                    @{
                        "GraphUri" = "administrativeUnits/{id}/extensions"
                        "Path" = "Extensions"
                        "Tag" = @("All", "Config")
                    }
                )
            },
            @{
                "GraphUri" = "identity/continuousAccessEvaluationPolicy"
                "Path" = "Identity/ContinuousAccessEvaluationPolicy"
                "Tag" = @("All", "Config")
            },
            @{
                "GraphUri" = "policies/permissionGrantPolicies"
                "Path" = "Policies/PermissionGrantPolicies"
                "Tag" = @("All", "Config")
            },
            @{
                "GraphUri" = "privilegedAccess/aadroles/resources"
                "Path" = "PrivilegedAccess/AADRoles/Resources"
                "Tag" = @("All", "Config", "PIM")
                Childrens = @(
                    @{
                        "GraphUri" = "privilegedAccess/aadroles/resources/{id}/roleDefinitions"
                        "Path" = "RoleDefinitions"
                        "Filter" = "Type ne 'BuiltInRole'"
                        "Tag" = @("All", "Config", "PIM")
                    },
                    @{
                        "GraphUri" = "privilegedAccess/aadroles/resources/{id}/roleSettings"
                        "Path" = "RoleSettings"
                        "Filter" = "isDefault eq false"
                        "Tag" = @("All", "Config", "PIM")
                    },
                    @{
                        "GraphUri" = "privilegedAccess/aadroles/resources/{id}/roleAssignments"
                        "Path" = "RoleAssignments"
                        "Filter" = "endDateTime eq null"
                        "Tag" = @("All", "Config", "PIM")
                    }
                )
            }
        )
    }
    $totalExports = $ExportSchema.Count
    $processedItems = 0    

    foreach ($item in $ExportSchema) {
        $typeMatch = Compare-Object $item.Tag $Type -ExcludeDifferent -IncludeEqual
        $hasParents = $Parents -and $Parents.Count -gt 0
        if( ($Type -contains 'All' -or $typeMatch)) {
            $outputFileName = Join-Path -Path $Path -ChildPath $item.Path

            $spacer = ''
            if($hasParents) { $spacer = ''.PadRight($Parents.Count + 3, ' ') + $Parents[$Parents.Count-1] }
            
            Write-Host "$spacer $($item.Path)"

            $command = Get-ObjectProperty $item 'Command'
            $graphUri = Get-ObjectProperty $item 'GraphUri'

            if($command) {
                if ($hasParents){ $command += " -Parents $Parents" }
                $resultItems = Invoke-Expression -Command $command
            }
            else {
                if ($hasParents){ $graphUri = $graphUri -replace '{id}', $Parents[$Parents.Count-1] }
                $resultItems = Invoke-Graph $graphUri -Filter (Get-ObjectProperty $item 'Filter') -Select (Get-ObjectProperty $item 'Select') -QueryParameters (Get-ObjectProperty $item 'QueryParameters')
            }

            if ($outputFileName -match "\.json$") {
                $resultItems | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
            } else {
                foreach($resultItem in $resultItems) {
                    if (!$resultItem.ContainsKey('id')) {
                        continue
                    }
                    $itemOutputFileName = Join-Path -Path $outputFileName -ChildPath $resultItem.id
                    $parentOutputFileName = Join-Path $itemOutputFileName -ChildPath $resultItem.id
                    $resultItem | ConvertTo-Json -depth 100 | Out-File (New-Item -Path "$($parentOutputFileName).json" -Force)
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