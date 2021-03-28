<# 
 .Synopsis
  Exports the Azure AD Configuration and settings for a tenant
 .Description
  This cmdlet reads the configuration information from the target Azure AD Tenant and produces the output files 
  in a target directory

 .PARAMETER OutputDirectory
    Specifies the directory path where the output files will be generated.

.PARAMETER Type
    Specifies the type of objects to export. Default to Config which exports the key configuration settings of the tenant.

.PARAMETER All
    If specified performs a full export of all objects and configuration in the tenant.

.EXAMPLE
   .\Invoke-AADExporter -Path "c:\temp\contoso"

.EXAMPLE
   .\Invoke-AADExporter -Path "c:\temp\contoso" -All

.EXAMPLE
   .\Invoke-AADExporter -Path "c:\temp\contoso" -Type ConditionalAccess, AppProxy

.EXAMPLE
   .\Invoke-AADExporter -Path "c:\temp\contoso" -Type B2C

#>

Function Invoke-AADExporter {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]$Path,        
        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Config', 'AccessReviews', 'ConditionalAccess', 'Users', 'Groups', 'Applications', 'ServicePrincipals','B2C','B2B','PIM','PIMAzure','PIMAAD', 'AppProxy')]
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
    $global:Type = $Type #Used in places like Groups where Config flag will limit the resultset to just dynamic groups.

    if (!$ExportSchema) {
        $ExportSchema = @(
            # Organization
            @{
                GraphUri = "organization" 
                Path = "Organization/Organization.json"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "organization/$($TenantID)/settings"
                Path = "Organization/Settings.json"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "organization/$($TenantID)/branding/localizations"
                Path = "Organization/Branding/Localizations.json"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "organization/$($TenantID)/certificateBasedAuthConfiguration"
                Path = "Organization/CertificateBasedAuthConfiguration.json"
                Tag = @("All", "Config")
            },

            @{
                GraphUri = "identity/apiConnectors"
                Path = "Identity/APIConnectors"
                Tag = @("All")
            },
            @{
                GraphUri = "domains"
                Path = "Domains"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "identityProviders"
                Path = "IdentityProviders"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "identity/continuousAccessEvaluationPolicy"
                Path = "Identity/ContinuousAccessEvaluationPolicy"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "subscribedSkus"
                Path = "SubscribedSkus"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "directoryRoles"
                Path = "DirectoryRoles"
                Tag = @("All", "Config")
                Children = @(
                    @{
                        GraphUri = "directoryRoles/{id}/members"
                        Select = "id, userPrincipalName, displayName"
                        Path = "Members"
                        Tag = @("All", "Config")
                    }
                    @{
                        GraphUri = "directoryroles/{id}/scopedMembers"
                        Path = "ScopedMembers"
                        Tag = @("All", "Config")
                    }
                )
            },
            # Applications
            @{
                GraphUri = "applications"
                Path = "Applications"
                Tag = @("All", "Applications")
                Children = @(
                    @{
                        GraphUri = "applications/{id}/extensionProperties"
                        Path = "ExtensionProperties"
                        Tag = @("All", "Applications")
                    },
                    @{
                        GraphUri = "applications/{id}/owners"
                        Select = "id, userPrincipalName, displayName"
                        Path = "Owners"
                        Tag = @("All", "Applications")
                    },
                    @{
                        GraphUri = "applications/{id}/tokenIssuancePolicies"
                        Path = "TokenIssuancePolicies"
                        Tag = @("All", "Applications")
                    },
                    @{
                        GraphUri = "applications/{id}/tokenLifetimePolicies"
                        Path = "TokenLifetimePolicies"
                        Tag = @("All", "Applications")
                    }
                )
            },
            @{
                GraphUri = "servicePrincipals"
                Path = "ServicePrincipals"
                Tag = @("All", "ServicePrincipals")
                Children = @(
                    @{
                        GraphUri = "servicePrincipals/{id}/appRoleAssignments"
                        Path = "AppRoleAssignments"
                        Tag = @("All", "ServicePrincipals")
                    },
                    @{
                        GraphUri = "servicePrincipals/{id}/oauth2PermissionGrants"
                        Path = "Oauth2PermissionGrants"
                        Tag = @("All", "ServicePrincipals")
                    },
                    @{
                        GraphUri = "servicePrincipals/{id}/delegatedPermissionClassifications"
                        Path = "DelegatedPermissionClassifications"
                        Tag = @("All", "ServicePrincipals")
                    },
                    @{
                        GraphUri = "servicePrincipals/{id}/owners"
                        Select = "id, userPrincipalName, displayName"
                        Path = "Owners"
                        Tag = @("All", "ServicePrincipals")
                    },
                    @{
                        GraphUri = "servicePrincipals/{id}/claimsMappingPolicies"
                        Path = "claimsMappingPolicies"
                        Tag = @("All", "ServicePrincipals")
                    },
                    @{
                        GraphUri = "servicePrincipals/{id}/homeRealmDiscoveryPolicies"
                        Path = "homeRealmDiscoveryPolicies"
                        Tag = @("All", "ServicePrincipals")
                    },
                    @{
                        GraphUri = "servicePrincipals/{id}/tokenIssuancePolicies"
                        Path = "tokenIssuancePolicies"
                        Tag = @("All", "ServicePrincipals")
                    },
                    @{
                        GraphUri = "servicePrincipals/{id}/tokenLifetimePolicies"
                        Path = "tokenLifetimePolicies"
                        Tag = @("All", "ServicePrincipals")
                    }
                )
            },
            
            # Users
            @{
                Command = "Get-AADExportUsers"
                Path = "Users"
                Tag = @("All", "Users")
                Children = @(
                    @{
                        GraphUri = "users/{id}/authentication/fido2Methods"
                        Path = "Authentication/FIDO2Methods"
                        Tag = @("All", "Users")
                    },
                    @{
                        GraphUri = "users/{id}/authentication/microsoftAuthenticatorMethods"
                        Path = "Authentication/MicrosoftAuthenticatorMethods"
                        Tag = @("All", "Users")
                    },
                    @{
                        GraphUri = "users/{id}/authentication/windowsHelloForBusinessMethods"
                        Path = "Authentication/WindowsHelloForBusinessMethods"
                        Tag = @("All", "Users")
                    },
                    @{
                        GraphUri = "users/{id}/authentication/temporaryAccessPassMethods"
                        Path = "Authentication/TemporaryAccessPassMethods"
                        Tag = @("All", "Users")
                    },
                    @{
                        GraphUri = "users/{id}/authentication/phoneMethods"
                        Path = "Authentication/PhoneMethods"
                        Tag = @("All", "Users")
                    },
                    @{
                        GraphUri = "users/{id}/authentication/emailMethods"
                        Path = "Authentication/EmailMethods"
                        Tag = @("All", "Users")
                    },
                    @{
                        GraphUri = "users/{id}/authentication/passwordMethods"
                        Path = "Authentication/PasswordMethods"
                        Tag = @("All", "Users")
                    },
                    @{
                        GraphUri = "users/{id}/extensions"
                        Path = "Extensions"
                        Tag = @("All", "Users")
                    }
                )
            },


            # Groups
            @{
                Command = "Get-AADExportGroups" 
                Path = "Groups"
                Tag = @("All", "Config", "Groups")
                Children = @(
                    @{
                        GraphUri = "groups/{id}/members" 
                        Select = "id, userPrincipalName, displayName"
                        Path = "Members"
                        Tag = @("All", "Groups")
                    }
                    @{
                        GraphUri =  "groups/{id}/owners"
                        Select = "id, userPrincipalName, displayName"
                        Path = "Owners"
                        Tag = @("All", "Config", "Groups")
                    },
                    @{
                        GraphUri = "groups/{id}/extensions"
                        Path = "Extensions"
                        Tag = @("All", "Groups")
                    }
                )                
            },
            @{
                GraphUri = "groupSettings"
                Path = "GroupSettings"
                Tag = @("All", "Config")
            },



            # B2C
            @{
                GraphUri = "identity/userFlows"
                Path = "Identity/UserFlows"
                Tag = @("B2C")
            },
            @{
                GraphUri = "identity/b2cUserFlows"
                QueryParameters = @{ expand = 'identityProviders' }
                Path = "Identity/B2CUserFlows"
                Tag = @("B2C")
            },
            @{
                GraphUri = "identity/userFlowAttributes"
                Path = "Identity/UserFlowAttributes"
                Tag = @("B2C")
            },
            @{
                GraphUri = "identity/b2cUserFlows"
                Path = "B2C/UserFlows"
                Tag = @("B2C")
                Children = @(
                    @{
                        GraphUri = "identity/b2cUserFlows/{id}/identityProviders"
                        Path = "IdentityProviders"
                        Tag = @("B2C")
                    },
                    @{
                        GraphUri = "identity/b2cUserFlows/{id}/userAttributeAssignments"
                        QueryParameters = @{ expand = 'userAttribute' }
                        Path = "AttributeAssignments"
                        Tag = @("B2C")
                    },
                    @{
                        GraphUri = "identity/b2cUserFlows/{id}/apiConnectorConfiguration"
                        QueryParameters = @{ expand = 'postFederationSignup,postAttributeCollection' }
                        Path = "APIConnectors"
                        Tag = @("B2C")
                    },
                    @{
                        GraphUri = "identity/b2cUserFlows/{id}/languages"
                        Path = "Languages"
                        Tag = @("B2C")
                    }
                )
            },
            @{
                GraphUri = "identity/b2xUserFlows"
                Path = "B2B/UserFlows"
                Tag = @("All","B2B")
                Children = @(
                    @{
                        GraphUri = "identity/b2xUserFlows/{id}/identityProviders"
                        Path = "IdentityProviders"
                        Tag = @("All","B2B")
                    },
                    @{
                        GraphUri = "identity/b2xUserFlows/{id}/userAttributeAssignments"
                        QueryParameters = @{ expand = 'userAttribute' }
                        Path = "AttributeAssignments"
                        Tag = @("All","B2B")
                    },
                    @{
                        GraphUri = "identity/b2xUserFlows/{id}/apiConnectorConfiguration"
                        QueryParameters = @{ expand = 'postFederationSignup,postAttributeCollection' }
                        Path = "APIConnectors"
                        Tag = @("All","B2B")
                    },
                    @{
                        GraphUri = "identity/b2xUserFlows/{id}/languages"
                        Path = "Languages"
                        Tag = @("All","B2B")
                    }
                )
            },


            # Policies
            @{
                GraphUri = "policies/identitySecurityDefaultsEnforcementPolicy"
                Path =  "Policies/IdentitySecurityDefaultsEnforcementPolicy"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/authorizationPolicy"
                Path = "Policies/AuthorizationPolicy"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/featureRolloutPolicies"
                Path = "Policies/FeatureRolloutPolicies"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/activityBasedTimeoutPolicies"
                Path = "Policies/ActivityBasedTimeoutPolicy"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/homeRealmDiscoveryPolicies"
                Path = "Policies/HomeRealmDiscoveryPolicy"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/claimsMappingPolicies"
                Path = "Policies/ClaimsMappingPolicy"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/tokenIssuancePolicies"
                Path = "Policies/TokenIssuancePolicy"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/tokenLifetimePolicies"
                Path = "Policies/TokenLifetimePolicy"
                Tag = @("All", "Config")
            },            
            @{
                GraphUri = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/email"
                Path = "Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/Email.json"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2"
                Path = "Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/FIDO2.json"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator"
                Path = "Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/MicrosoftAuthenticator.json"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms"
                Path = "Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/SMS.json"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass"
                Path = "Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/TemporaryAccessPass.json"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/adminConsentRequestPolicy"
                Path = "Policies/AdminConsentRequestPolicy"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "policies/permissionGrantPolicies"
                Path = "Policies/PermissionGrantPolicies"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "identity/conditionalAccess/policies"
                Path =  "Identity/Conditional/AccessPolicies"
                Tag = @("All", "Config", "ConditionalAccess")
            },
            @{
                GraphUri = "identity/conditionalAccess/namedLocations"
                Path =  "Identity/Conditional/NamedLocations"
                Tag = @("All", "Config", "ConditionalAccess")
            },

            # Identity Governance
            @{
                GraphUri = "identityGovernance/entitlementManagement/accessPackages"
                Path = "IdentityGovernance\EntitlementManagement\AccessPackages"
                Tag = @("All", "Config")
                Children = @(
                    @{
                        Command = "Get-AADExportAccessPackageAssignmentPolicies"
                        Path = "AssignmentPolicies"
                        Tag = @("All", "Config")
                    },
                    @{
                        Command = "Get-AADExportAccessPackageAssignments"
                        Path = "Assignments"
                        Tag = @("All", "Config")
                    },
                    @{
                        Command = "Get-AADExportAccessPackageResourceScopes"
                        Path = "ResourceScopes"
                        Tag = @("All", "Config")
                    }
                )
            },
            @{
                GraphUri = "businessFlowTemplates"
                Path = "IdentityGovernance/AccessReviews"
                Tag = @("All","Config", "AccessReviews")
                Children = @(
                    @{
                        Command = "Get-AADExportAccessReviews"
                        Path = ""
                        Tag = @("All","Config", "AccessReviews")
                        Children = @(
                            @{
                                GraphUri = "accessReviews/{id}/reviewers"
                                Path = "Reviewers"
                                Tag = @("All","Config", "AccessReviews")
                            }
                        )
                    }
                )
            },
            @{
                GraphUri = "identityGovernance/termsOfUse/agreements"
                Path = "IdentityGovernance/TermsOfUse/Agreements"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "identityGovernance/entitlementManagement/connectedOrganizations"
                Path = "IdentityGovernance/EntitlementManagement/ConnectedOrganizations"
                Tag = @("All", "Config")
                Children = @(
                    @{
                        GraphUri = "identityGovernance/entitlementManagement/connectedOrganizations/{id}/externalSponsors"
                        Path = "ExternalSponsors"
                        Tag = @("All", "Config")
                    },
                    @{
                        GraphUri = "identityGovernance/entitlementManagement/connectedOrganizations/{id}/internalSponsors"
                        Path = "InternalSponsors"
                        Tag = @("All", "Config")
                    }
                )    
            },            
            @{
                GraphUri = "identityGovernance/entitlementManagement/settings"
                Path = "IdentityGovernance/EntitlementManagement/Settings"
                Tag = @("All", "Config")
            },
            @{
                GraphUri = "AdministrativeUnits"
                Path = "AdministrativeUnits"
                Tag = @("All", "Config")
                Children = @(
                    @{
                        GraphUri = "administrativeUnits/{id}/members"
                        Path = "Members"
                        Select = "Id"
                        Tag = @("All", "Config")
                    },
                    @{
                        GraphUri = "administrativeUnits/{id}/scopedRoleMembers"
                        Path = "ScopedRoleMembers"
                        Tag = @("All", "Config")
                    },
                    @{
                        GraphUri = "administrativeUnits/{id}/extensions"
                        Path = "Extensions"
                        Tag = @("All", "Config")
                    }
                )
            },

            # PIM
            @{
                GraphUri = "privilegedAccess/aadroles/resources"
                Path = "PrivilegedAccess/AADRoles/Resources"
                Tag = @("All", "Config", "PIM", "PIMAAD")
                Children = @(
                    @{
                        GraphUri = "privilegedAccess/aadroles/resources/{id}/roleDefinitions"
                        Path = "RoleDefinitions"
                        #"Filter" = "Type ne 'BuiltInRole'"
                        Tag = @("All", "Config", "PIM", "PIMAAD")
                    },
                    @{
                        GraphUri = "privilegedAccess/aadroles/resources/{id}/roleSettings"
                        Path = "RoleSettings"
                        #"Filter" = "isDefault eq false"
                        Tag = @("All", "Config", "PIM", "PIMAAD")
                    },
                    @{
                        GraphUri = "privilegedAccess/aadroles/resources/{id}/roleAssignments"
                        Path = "RoleAssignments"
                        #"Filter" = "endDateTime eq null"
                        Tag = @("All", "Config", "PIM", "PIMAAD")
                    }
                )
            },
            @{
                GraphUri = "privilegedAccess/azureResources/resources"
                Path = "PrivilegedAccess/AzureResources/Resources"
                Tag = @("All", "Config", "PIM", "PIMAzure")
                Children = @(
                    @{
                        GraphUri = "privilegedAccess/azureResources/resources/{id}/roleDefinitions"
                        Path = "RoleDefinitions"
                        #"Filter" = "Type ne 'BuiltInRole'"
                        Tag = @("All", "PIM", "PIMAAzure")
                    },
                    @{
                        GraphUri = "privilegedAccess/azureResources/resources/{id}/roleSettings"
                        Path = "RoleSettings"
                        #"Filter" = "isDefault eq false"
                        Tag = @("All", "PIM", "PIMAAzure")
                    },
                    @{
                        GraphUri = "privilegedAccess/azureResources/resources/{id}/roleAssignments"
                        Path = "RoleAssignments"
                        #"Filter" = "endDateTime eq null"
                        Tag = @("All", "PIM", "PIMAzure")
                    }
                )
            },

            #Application Proxy
            @{
                GraphUri = "onPremisesPublishingProfiles/provisioning"
                QueryParameters = @{ expand = 'publishedResources,agents,agentGroups' }
                Path = "OnPremisesPublishingProfiles/Provisioning.json"
                Tag = @("All", "Config", "AppProxy")
            },
            @{
                GraphUri = "onPremisesPublishingProfiles/provisioning/publishedResources"
                QueryParameters = @{ expand = 'agentGroups' }
                Path = "OnPremisesPublishingProfiles/Provisioning/PublishedResources"
                Tag = @("All", "Config", "AppProxy")
            },
            @{
                GraphUri = "onPremisesPublishingProfiles/provisioning/agentGroups"
                QueryParameters = @{ expand = 'agents,publishedResources' }
                Path = "OnPremisesPublishingProfiles/Provisioning/AgentGroups"
                Tag = @("All", "Config", "AppProxy")
            },
            @{
                GraphUri = "onPremisesPublishingProfiles/provisioning/agents"
                QueryParameters = @{ expand = 'agentGroups' }
                Path = "OnPremisesPublishingProfiles/Provisioning/Agents"
                Tag = @("All", "Config", "AppProxy")
            },
            @{
                GraphUri = "onPremisesPublishingProfiles/applicationProxy/connectors"
                Path = "OnPremisesPublishingProfiles/ApplicationProxy/Connectors"
                Tag = @("All", "Config", "AppProxy")
            },
            @{
                GraphUri = "onPremisesPublishingProfiles/applicationProxy/connectorGroups"
                Path = "OnPremisesPublishingProfiles/ApplicationProxy/ConnectorGroups"
                Tag = @("All", "Config", "AppProxy")
                Children = @(
                    @{
                        GraphUri = "onPremisesPublishingProfiles/applicationProxy/connectorGroups/{id}/applications"
                        Path = "Applications"
                        Tag = @("All", "Config", "AppProxy")
                    },
                    @{
                        GraphUri = "onPremisesPublishingProfiles/applicationProxy/connectorGroups/{id}/members"
                        Path = "Members"
                        Tag = @("All", "Config", "AppProxy")
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
        if( ($typeMatch)) {
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
                ConvertTo-OrderedDictionary $resultItems | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
            } else {
                foreach($resultItem in $resultItems) {
                    if (!$resultItem.ContainsKey('id')) {
                        continue
                    }
                    $itemOutputFileName = Join-Path -Path $outputFileName -ChildPath $resultItem.id
                    $parentOutputFileName = Join-Path $itemOutputFileName -ChildPath $resultItem.id
                    ConvertTo-OrderedDictionary $resultItem | ConvertTo-Json -depth 100 | Out-File (New-Item -Path "$($parentOutputFileName).json" -Force)
                    if ($item.ContainsKey('Children')) {
                        $itemParents = $Parents
                        $itemParents += $resultItem.Id
                        Invoke-AADExporter -Path $itemOutputFileName -Type $Type -ExportSchema $item.Children -Parents $itemParents
                    }
                }
            }
        }

        $processedItems++
    }
}