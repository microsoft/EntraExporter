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
   .\Invoke-AADExporter -Path 'c:\temp\contoso'

   Runs a default export and includes the key tenant configuration settings. Does not include large data collections such as Users, Groups, Applications, Service Principals, etc.
.EXAMPLE
   .\Invoke-AADExporter -Path 'c:\temp\contoso' -All
   
   Runs a full export of all objects and configuration settings.

.EXAMPLE
   .\Invoke-AADExporter -Path 'c:\temp\contoso' -Type ConditionalAccess, AppProxy

   Runs an export that includes just the Conditional Access and Application Proxy settings.

.EXAMPLE
   .\Invoke-AADExporter -Path 'c:\temp\contoso' -Type B2C

   Runs an export of all B2C settings.
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
        $All,
        [switch]
        $CloudUsersAndGroupsOnly,
        [switch]
        $AllGroups
    )

    if ($null -eq (Get-MgContext)) {
        Write-Error "No active connection. Run Connect-AADExporter to sign in and then retry."
        exit
    }
    if($All) {$Type = @('All')}
    $global:TenantID = (Get-MgContext).TenantId
    $global:Type = $Type #Used in places like Groups where Config flag will limit the resultset to just dynamic groups.

    if (!$ExportSchema) {
        $ExportSchema = @(
            # Organization
            @{
                GraphUri = 'organization' 
                Path = 'Organization/Organization.json'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'organization/{0}/settings' -f $TenantID
                Path = 'Organization/Settings.json'
                ApiVersion = 'beta'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'organization/{0}/branding/localizations' -f $TenantID
                Path = 'Organization/Branding/Localizations.json'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'organization/{0}/certificateBasedAuthConfiguration' -f $TenantID
                Path = 'Organization/CertificateBasedAuthConfiguration.json'
                Tag = @('All', 'Config')
            },

            @{
                GraphUri = 'identity/apiConnectors'
                Path = 'Identity/APIConnectors'
                ApiVersion = 'beta'
                IgnoreError = 'The feature self service sign up is not enabled for the tenant'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'domains'
                Path = 'Domains'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'identityProviders'
                Path = 'IdentityProviders'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'identity/continuousAccessEvaluationPolicy'
                Path = 'Identity/ContinuousAccessEvaluationPolicy'
                ApiVersion = 'beta'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'subscribedSkus'
                Path = 'SubscribedSkus'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'directoryRoles'
                Path = 'DirectoryRoles'
                Tag = @('All', 'Config')
                Children = @(
                    @{
                        GraphUri = 'directoryRoles/{id}/members'
                        Select = 'id, userPrincipalName, displayName'
                        Path = 'Members'
                        Tag = @('All', 'Config')
                    }
                    @{
                        GraphUri = 'directoryroles/{id}/scopedMembers'
                        Path = 'ScopedMembers'
                        Tag = @('All', 'Config')
                    }
                )
            },

            # B2C
            @{
                GraphUri = 'identity/userFlows'
                Path = 'Identity/UserFlows'
                Tag = @('B2C')
            },
            @{
                GraphUri = 'identity/b2cUserFlows'
                Path = 'Identity/B2CUserFlows'
                Tag = @('B2C')
                Children = @(
                    @{
                        GraphUri = 'identity/b2cUserFlows/{id}/identityProviders'
                        Path = 'IdentityProviders'
                        Tag = @('B2C')
                    },
                    @{
                        GraphUri = 'identity/b2cUserFlows/{id}/userAttributeAssignments'
                        QueryParameters = @{ expand = 'userAttribute' }
                        Path = 'UserAttributeAssignments'
                        Tag = @('B2C')
                    },
                    @{
                        GraphUri = 'identity/b2cUserFlows/{id}/apiConnectorConfiguration'
                        QueryParameters = @{ expand = 'postFederationSignup,postAttributeCollection' }
                        Path = 'ApiConnectorConfiguration'
                        Tag = @('B2C')
                    },
                    @{
                        GraphUri = 'identity/b2cUserFlows/{id}/languages'
                        Path = 'Languages'
                        Tag = @('B2C')
                    }
                )
            },

            # B2B
            @{
                GraphUri = 'identity/userFlowAttributes'
                Path = 'Identity/UserFlowAttributes'
                ApiVersion = 'beta'
                Tag = @('Config', 'B2B', 'B2C')
            },
            @{
                GraphUri = 'identity/b2xUserFlows'
                Path = 'Identity/B2XUserFlows'
                ApiVersion = 'beta'
                Tag = @('All', 'Config', 'B2B')
                Children = @(
                    @{
                        GraphUri = 'identity/b2xUserFlows/{id}/identityProviders'
                        Path = 'IdentityProviders'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Config', 'B2B')
                    },
                    @{
                        GraphUri = 'identity/b2xUserFlows/{id}/userAttributeAssignments'
                        QueryParameters = @{ expand = 'userAttribute' }
                        Path = 'AttributeAssignments'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Config', 'B2B')
                    },
                    @{
                        GraphUri = 'identity/b2xUserFlows/{id}/apiConnectorConfiguration'
                        QueryParameters = @{ expand = 'postFederationSignup,postAttributeCollection' }
                        Path = 'APIConnectors'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Config', 'B2B')
                    },
                    @{
                        GraphUri = 'identity/b2xUserFlows/{id}/languages'
                        Path = 'Languages'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Config', 'B2B')
                    }
                )
            },

            # Policies
            @{
                GraphUri = 'policies/identitySecurityDefaultsEnforcementPolicy'
                Path =  'Policies/IdentitySecurityDefaultsEnforcementPolicy'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/authorizationPolicy'
                Path = 'Policies/AuthorizationPolicy'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/featureRolloutPolicies'
                Path = 'Policies/FeatureRolloutPolicies'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/activityBasedTimeoutPolicies'
                Path = 'Policies/ActivityBasedTimeoutPolicy'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/homeRealmDiscoveryPolicies'
                Path = 'Policies/HomeRealmDiscoveryPolicy'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/claimsMappingPolicies'
                Path = 'Policies/ClaimsMappingPolicy'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/tokenIssuancePolicies'
                Path = 'Policies/TokenIssuancePolicy'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/tokenLifetimePolicies'
                Path = 'Policies/TokenLifetimePolicy'
                Tag = @('All', 'Config')
            },            
            @{
                GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/email'
                Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/Email.json'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'
                Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/FIDO2.json'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator'
                Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/MicrosoftAuthenticator.json'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms'
                Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/SMS.json'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass'
                Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/TemporaryAccessPass.json'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/adminConsentRequestPolicy'
                Path = 'Policies/AdminConsentRequestPolicy'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'policies/permissionGrantPolicies'
                Path = 'Policies/PermissionGrantPolicies'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'identity/conditionalAccess/policies'
                Path =  'Identity/Conditional/AccessPolicies'
                Tag = @('All', 'Config', 'ConditionalAccess')
            },
            @{
                GraphUri = 'identity/conditionalAccess/namedLocations'
                Path =  'Identity/Conditional/NamedLocations'
                Tag = @('All', 'Config', 'ConditionalAccess')
            },

            # Identity Governance
            @{
                GraphUri = 'identityGovernance/entitlementManagement/accessPackages'
                Path = 'IdentityGovernance\EntitlementManagement\AccessPackages'
                ApiVersion = 'beta'
                Tag = @('All', 'Config')
                Children = @(
                    @{
                        Command = 'Get-AADExportAccessPackageAssignmentPolicies'
                        Path = 'AssignmentPolicies'
                        Tag = @('All', 'Config')
                    },
                    @{
                        Command = 'Get-AADExportAccessPackageAssignments'
                        Path = 'Assignments'
                        Tag = @('All', 'Config')
                    },
                    @{
                        Command = 'Get-AADExportAccessPackageResourceScopes'
                        Path = 'ResourceScopes'
                        Tag = @('All', 'Config')
                    }
                )
            },
            @{
                GraphUri = 'businessFlowTemplates'
                Path = 'IdentityGovernance/AccessReviews'
                ApiVersion = 'beta'
                Tag = @('All','Config', 'AccessReviews')
                Children = @(
                    @{
                        Command = 'Get-AADExportAccessReviews'
                        Path = ''
                        Tag = @('All','Config', 'AccessReviews')
                        Children = @(
                            @{
                                GraphUri = 'accessReviews/{id}/reviewers'
                                Path = 'Reviewers'
                                ApiVersion = 'beta'
                                Tag = @('All','Config', 'AccessReviews')
                            }
                        )
                    }
                )
            },
            @{
                GraphUri = 'identityGovernance/termsOfUse/agreements'
                Path = 'IdentityGovernance/TermsOfUse/Agreements'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'identityGovernance/entitlementManagement/connectedOrganizations'
                Path = 'IdentityGovernance/EntitlementManagement/ConnectedOrganizations'
                ApiVersion = 'beta'
                Tag = @('All', 'Config')
                Children = @(
                    @{
                        GraphUri = 'identityGovernance/entitlementManagement/connectedOrganizations/{id}/externalSponsors'
                        Path = 'ExternalSponsors'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Config')
                    },
                    @{
                        GraphUri = 'identityGovernance/entitlementManagement/connectedOrganizations/{id}/internalSponsors'
                        Path = 'InternalSponsors'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Config')
                    }
                )    
            },            
            @{
                GraphUri = 'identityGovernance/entitlementManagement/settings'
                Path = 'IdentityGovernance/EntitlementManagement/Settings'
                ApiVersion = 'beta'
                Tag = @('All', 'Config')
            },
            @{
                GraphUri = 'AdministrativeUnits'
                Path = 'AdministrativeUnits'
                ApiVersion = 'beta'
                Tag = @('All', 'Config')
                Children = @(
                    @{
                        GraphUri = 'administrativeUnits/{id}/members'
                        Select = 'Id'
                        Path = 'Members'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Config')
                    },
                    @{
                        GraphUri = 'administrativeUnits/{id}/scopedRoleMembers'
                        Path = 'ScopedRoleMembers'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Config')
                    },
                    @{
                        GraphUri = 'administrativeUnits/{id}/extensions'
                        Path = 'Extensions'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Config')
                    }
                )
            },

            # PIM
            @{
                GraphUri = 'privilegedAccess/aadroles/resources'
                Path = 'PrivilegedAccess/AADRoles/Resources'
                ApiVersion = 'beta'
                Tag = @('All', 'Config', 'PIM', 'PIMAAD')
                Children = @(
                    @{
                        GraphUri = 'privilegedAccess/aadroles/resources/{id}/roleDefinitions'
                        Path = 'RoleDefinitions'
                        ApiVersion = 'beta'
                        Filter = "Type ne 'BuiltInRole'"
                        Tag = @('All', 'Config', 'PIM', 'PIMAAD')
                    },
                    @{
                        GraphUri = 'privilegedAccess/aadroles/resources/{id}/roleSettings'
                        Path = 'RoleSettings'
                        ApiVersion = 'beta'
                        Filter = 'isDefault eq false'
                        Tag = @('All', 'Config', 'PIM', 'PIMAAD')
                    },
                    @{
                        GraphUri = 'privilegedAccess/aadroles/resources/{id}/roleAssignments'
                        Path = 'RoleAssignments'
                        ApiVersion = 'beta'
                        Filter = 'endDateTime eq null'
                        Tag = @('All', 'Config', 'PIM', 'PIMAAD')
                    }
                )
            },
            @{
                GraphUri = 'privilegedAccess/azureResources/resources'
                Path = 'PrivilegedAccess/AzureResources/Resources'
                ApiVersion = 'beta'
                IgnoreError = 'The tenant has not onboarded to PIM.'
                Tag = @('All', 'Config', 'PIM', 'PIMAzure')
                Children = @(
                    @{
                        GraphUri = 'privilegedAccess/azureResources/resources/{id}/roleDefinitions'
                        Path = 'RoleDefinitions'
                        ApiVersion = 'beta'
                        Filter = "Type ne 'BuiltInRole'"
                        Tag = @('All', 'Config', 'PIM', 'PIMAAzure')
                    },
                    @{
                        GraphUri = 'privilegedAccess/azureResources/resources/{id}/roleSettings'
                        Path = 'RoleSettings'
                        ApiVersion = 'beta'
                        Filter = 'isDefault eq false'
                        Tag = @('All', 'Config', 'PIM', 'PIMAAzure')
                    },
                    @{
                        GraphUri = 'privilegedAccess/azureResources/resources/{id}/roleAssignments'
                        Path = 'RoleAssignments'
                        ApiVersion = 'beta'
                        Filter = 'endDateTime eq null'
                        Tag = @('All', 'Config', 'PIM', 'PIMAzure')
                    }
                )
            },

            #Application Proxy
            @{
                GraphUri = 'onPremisesPublishingProfiles/provisioning'
                QueryParameters = @{ expand = 'publishedResources,agents,agentGroups' }
                Path = 'OnPremisesPublishingProfiles/Provisioning.json'
                ApiVersion = 'beta'
                Tag = @('All', 'Config', 'AppProxy')
            },
            @{
                GraphUri = 'onPremisesPublishingProfiles/provisioning/publishedResources'
                QueryParameters = @{ expand = 'agentGroups' }
                Path = 'OnPremisesPublishingProfiles/Provisioning/PublishedResources'
                ApiVersion = 'beta'
                Tag = @('All', 'Config', 'AppProxy')
            },
            @{
                GraphUri = 'onPremisesPublishingProfiles/provisioning/agentGroups'
                QueryParameters = @{ expand = 'agents,publishedResources' }
                Path = 'OnPremisesPublishingProfiles/Provisioning/AgentGroups'
                ApiVersion = 'beta'
                Tag = @('All', 'Config', 'AppProxy')
            },
            @{
                GraphUri = 'onPremisesPublishingProfiles/provisioning/agents'
                QueryParameters = @{ expand = 'agentGroups' }
                Path = 'OnPremisesPublishingProfiles/Provisioning/Agents'
                ApiVersion = 'beta'
                Tag = @('All', 'Config', 'AppProxy')
            },
            @{
                GraphUri = 'onPremisesPublishingProfiles/applicationProxy/connectors'
                Path = 'OnPremisesPublishingProfiles/ApplicationProxy/Connectors'
                ApiVersion = 'beta'
                Tag = @('All', 'Config', 'AppProxy')
            },
            @{
                GraphUri = 'onPremisesPublishingProfiles/applicationProxy/connectorGroups'
                Path = 'OnPremisesPublishingProfiles/ApplicationProxy/ConnectorGroups'
                ApiVersion = 'beta'
                Tag = @('All', 'Config', 'AppProxy')
                Children = @(
                    @{
                        GraphUri = 'onPremisesPublishingProfiles/applicationProxy/connectorGroups/{id}/applications'
                        Path = 'Applications'
                        ApiVersion = 'beta'
                        IgnoreError = 'ApplicationsForGroup_NotFound'
                        Tag = @('All', 'Config', 'AppProxy')
                    },
                    @{
                        GraphUri = 'onPremisesPublishingProfiles/applicationProxy/connectorGroups/{id}/members'
                        Path = 'Members'
                        ApiVersion = 'beta'
                        IgnoreError = 'ConnectorGroup_NotFound'
                        Tag = @('All', 'Config', 'AppProxy')
                    }
                )
            },

            # Groups
            # need to looks at app roles assignements
            # expanding app roles assignements breaks 'ne' filtering (needs eventual consistency and count)
            @{
                GraphUri = 'groups'
                Filter = "groupTypes/any(c:c eq 'DynamicMembership')" 
                Path = 'Groups'
                QueryParameters = @{ '$count' = 'true'; expand = 'extensions' }
                ApiVersion = 'beta'
                Tag = @('All', 'Config', 'Groups')
                Children = @(
                    @{
                        GraphUri = 'groups/{id}/members' 
                        Select = 'id, userPrincipalName, displayName'
                        Path = 'Members'
                        Tag = @('All', 'Groups')
                    }
                    @{
                        GraphUri =  'groups/{id}/owners'
                        Select = 'id, userPrincipalName, displayName'
                        Path = 'Owners'
                        Tag = @('All', 'Config', 'Groups')
                    }
                )                
            },
            @{
                GraphUri = 'groupSettings'
                Path = 'GroupSettings'
                Tag = @('All', 'Config')
            },

            # Applications
            @{
                GraphUri = 'applications'
                Path = 'Applications'
                Tag = @('All', 'Applications')
                Children = @(
                    @{
                        GraphUri = 'applications/{id}/extensionProperties'
                        Path = 'ExtensionProperties'
                        Tag = @('All', 'Applications')
                    },
                    @{
                        GraphUri = 'applications/{id}/owners'
                        Select = 'id, userPrincipalName, displayName'
                        Path = 'Owners'
                        Tag = @('All', 'Applications')
                    },
                    @{
                        GraphUri = 'applications/{id}/tokenIssuancePolicies'
                        Path = 'TokenIssuancePolicies'
                        Tag = @('All', 'Applications')
                    },
                    @{
                        GraphUri = 'applications/{id}/tokenLifetimePolicies'
                        Path = 'TokenLifetimePolicies'
                        Tag = @('All', 'Applications')
                    }
                )
            },

            # Service Principals
            @{
                GraphUri = 'servicePrincipals'
                Path = 'ServicePrincipals'
                Tag = @('All', 'ServicePrincipals')
                Children = @(
                    @{
                        GraphUri = 'servicePrincipals/{id}/appRoleAssignments'
                        Path = 'AppRoleAssignments'
                        Tag = @('All', 'ServicePrincipals')
                    },
                    @{
                        GraphUri = 'servicePrincipals/{id}/oauth2PermissionGrants'
                        Path = 'Oauth2PermissionGrants'
                        Tag = @('All', 'ServicePrincipals')
                    },
                    @{
                        GraphUri = 'servicePrincipals/{id}/delegatedPermissionClassifications'
                        Path = 'DelegatedPermissionClassifications'
                        Tag = @('All', 'ServicePrincipals')
                    },
                    @{
                        GraphUri = 'servicePrincipals/{id}/owners'
                        Select = 'id, userPrincipalName, displayName'
                        Path = 'Owners'
                        Tag = @('All', 'ServicePrincipals')
                    },
                    @{
                        GraphUri = 'servicePrincipals/{id}/claimsMappingPolicies'
                        Path = 'claimsMappingPolicies'
                        Tag = @('All', 'ServicePrincipals')
                    },
                    @{
                        GraphUri = 'servicePrincipals/{id}/homeRealmDiscoveryPolicies'
                        Path = 'homeRealmDiscoveryPolicies'
                        Tag = @('All', 'ServicePrincipals')
                    },
                    @{
                        GraphUri = 'servicePrincipals/{id}/tokenIssuancePolicies'
                        Path = 'tokenIssuancePolicies'
                        Tag = @('All', 'ServicePrincipals')
                    },
                    @{
                        GraphUri = 'servicePrincipals/{id}/tokenLifetimePolicies'
                        Path = 'tokenLifetimePolicies'
                        Tag = @('All', 'ServicePrincipals')
                    }
                )
            },
            
            # Users
            # Todo look at app roles assignments
            @{
                GraphUri = 'users'
                Path = 'Users'
                Filter = $null
                QueryParameters = @{ '$count' = 'true'; expand = "extensions" }
                ApiVersion = 'beta'
                Tag = @('All', 'Users')
                Children = @(
                    @{
                        GraphUri = 'users/{id}/authentication/fido2Methods'
                        Path = 'Authentication/FIDO2Methods'
                        Tag = @('All', 'Users')
                    },
                    @{
                        GraphUri = 'users/{id}/authentication/microsoftAuthenticatorMethods'
                        Path = 'Authentication/MicrosoftAuthenticatorMethods'
                        Tag = @('All', 'Users')
                    },
                    @{
                        GraphUri = 'users/{id}/authentication/windowsHelloForBusinessMethods'
                        Path = 'Authentication/WindowsHelloForBusinessMethods'
                        Tag = @('All', 'Users')
                    },
                    @{
                        GraphUri = 'users/{id}/authentication/temporaryAccessPassMethods'
                        Path = 'Authentication/TemporaryAccessPassMethods'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Users')
                    },
                    @{
                        GraphUri = 'users/{id}/authentication/phoneMethods'
                        Path = 'Authentication/PhoneMethods'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Users')
                    },
                    @{
                        GraphUri = 'users/{id}/authentication/emailMethods'
                        Path = 'Authentication/EmailMethods'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Users')
                    },
                    @{
                        GraphUri = 'users/{id}/authentication/passwordMethods'
                        Path = 'Authentication/PasswordMethods'
                        ApiVersion = 'beta'
                        Tag = @('All', 'Users')
                    }
                )
            }
        )
    }
    

    # aditional filters
    foreach ($entry in $ExportSchema) {
        $graphUri = Get-ObjectProperty $entry "GraphUri"
        # filter out synced users or groups
        if ($CloudUsersAndGroupsOnly -and ($graphUri -in "users","groups")) {
            $entry.Filter = "onPremisesSyncEnabled ne true"
        }
        # get all groups
        if (($All -or $AllGroups) -and ($graphUri -eq "groups")) {
            $entry.Filter = $null
        }
        # get all PIM elements
        if ($All -and ($graphUri -in "privilegedAccess/aadroles/resources","privilegedAccess/azureResources/resources")) {
            $entry.Fitler = $null
        }
    }

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
            $apiVersion = Get-ObjectProperty $item 'ApiVersion'
            $ignoreError = Get-ObjectProperty $item 'IgnoreError'
            if (!$apiVersion) { $apiVersion = 'v1.0' }
            $resultItems = $null
            if($command) {
                if ($hasParents){ $command += " -Parents $Parents" }
                $resultItems = Invoke-Expression -Command $command
            }
            else {
                if ($hasParents){ $graphUri = $graphUri -replace '{id}', $Parents[$Parents.Count-1] }
                try {
                    $resultItems = Invoke-Graph $graphUri -Filter (Get-ObjectProperty $item 'Filter') -Select (Get-ObjectProperty $item 'Select') -QueryParameters (Get-ObjectProperty $item 'QueryParameters') -ApiVersion $apiVersion
                }
                catch {
                    $e = $_.ErrorDetails.Message
                    if($e.Contains($ignoreError) -or $e.Contains('Encountered an internal server error')){
                        Write-Debug $_
                    }
                    else {
                        Write-Error $_
                    }
                }
            }

            if ($outputFileName -match "\.json$") {
                if($resultItems){
                    ConvertTo-OrderedDictionary $resultItems | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
                }
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
    }
}