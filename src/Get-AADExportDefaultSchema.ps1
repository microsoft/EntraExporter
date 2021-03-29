<# 
 .Synopsis
  Gets the default export schema definition

 .Description
  Gets the default export schema definition. Defining the order in which elements are exported.

 .Example
  Get-AADExportDefaultSchema
#>

function Get-AADExportDefaultSchema()  {
    return  @(
        # Organization
        @{
            GraphUri = 'organization' 
            Path = 'Organization/Organization.json'
            Tag = @('All', 'Config', 'Organization')
        },
        @{
            GraphUri = 'organization/{0}/settings' -f $TenantID
            Path = 'Organization/Settings.json'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Organization')
        },
        @{
            GraphUri = 'organization/{0}/branding/localizations' -f $TenantID
            Path = 'Organization/Branding/Localizations.json'
            Tag = @('All', 'Config', 'Organization')
        },
        @{
            GraphUri = 'organization/{0}/certificateBasedAuthConfiguration' -f $TenantID
            Path = 'Organization/CertificateBasedAuthConfiguration.json'
            Tag = @('All', 'Config', 'Organization')
        },

        @{
            GraphUri = 'domains'
            Path = 'Domains'
            Tag = @('All', 'Config','Domains')
        },
        @{
            GraphUri = 'identity/apiConnectors'
            Path = 'Identity/APIConnectors'
            ApiVersion = 'beta'
            IgnoreError = 'The feature self service sign up is not enabled for the tenant'
            Tag = @('All', 'Config', 'Identity')
        },
        @{
            GraphUri = 'identityProviders'
            Path = 'IdentityProviders'
            Tag = @('All', 'Config', 'Identity')
        },
        @{
            GraphUri = 'identity/continuousAccessEvaluationPolicy'
            Path = 'Identity/ContinuousAccessEvaluationPolicy'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Identity')
        },
        @{
            GraphUri = 'subscribedSkus'
            Path = 'SubscribedSkus'
            Tag = @('All', 'Config', 'SKUs')
        },
        @{
            GraphUri = 'directoryRoles'
            Path = 'DirectoryRoles'
            Tag = @('All', 'Config', 'Roles')
            Children = @(
                @{
                    GraphUri = 'directoryRoles/{id}/members'
                    Select = 'id, userPrincipalName, displayName'
                    Path = 'Members'
                    Tag = @('All', 'Config', 'Roles')
                }
                @{
                    GraphUri = 'directoryroles/{id}/scopedMembers'
                    Path = 'ScopedMembers'
                    Tag = @('All', 'Config', 'Roles')
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
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/authorizationPolicy'
            Path = 'Policies/AuthorizationPolicy'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/featureRolloutPolicies'
            Path = 'Policies/FeatureRolloutPolicies'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/activityBasedTimeoutPolicies'
            Path = 'Policies/ActivityBasedTimeoutPolicy'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/homeRealmDiscoveryPolicies'
            Path = 'Policies/HomeRealmDiscoveryPolicy'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/claimsMappingPolicies'
            Path = 'Policies/ClaimsMappingPolicy'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/tokenIssuancePolicies'
            Path = 'Policies/TokenIssuancePolicy'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/tokenLifetimePolicies'
            Path = 'Policies/TokenLifetimePolicy'
            Tag = @('All', 'Config', 'Policies')
        },            
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/email'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/Email.json'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/FIDO2.json'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/MicrosoftAuthenticator.json'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/SMS.json'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/TemporaryAccessPass.json'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/adminConsentRequestPolicy'
            Path = 'Policies/AdminConsentRequestPolicy'
            Tag = @('All', 'Config', 'Policies')
        },
        @{
            GraphUri = 'policies/permissionGrantPolicies'
            Path = 'Policies/PermissionGrantPolicies'
            Tag = @('All', 'Config', 'Policies')
        },
        # Conditional Access
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
            Tag = @('All', 'Config', 'Governance', 'EntitlementManagement')
            Children = @(
                @{
                    Command = 'Get-AADExportAccessPackageAssignmentPolicies'
                    Path = 'AssignmentPolicies'
                    Tag = @('All', 'Config', 'Governance', 'EntitlementManagement')
                },
                @{
                    Command = 'Get-AADExportAccessPackageAssignments'
                    Path = 'Assignments'
                    Tag = @('All', 'Config', 'Governance', 'EntitlementManagement')
                },
                @{
                    Command = 'Get-AADExportAccessPackageResourceScopes'
                    Path = 'ResourceScopes'
                    Tag = @('All', 'Config', 'Governance', 'EntitlementManagement')
                }
            )
        },
        @{
            GraphUri = 'businessFlowTemplates'
            Path = 'IdentityGovernance/AccessReviews'
            ApiVersion = 'beta'
            Tag = @('All','Config', 'AccessReviews', 'Governance')
            Children = @(
                @{
                    Command = 'Get-AADExportAccessReviews'
                    Path = ''
                    Tag = @('All','Config', 'AccessReviews', 'Governance')
                    Children = @(
                        @{
                            GraphUri = 'accessReviews/{id}/reviewers'
                            Path = 'Reviewers'
                            ApiVersion = 'beta'
                            Tag = @('All','Config', 'AccessReviews', 'Governance')
                        }
                    )
                }
            )
        },
        @{
            GraphUri = 'identityGovernance/termsOfUse/agreements'
            Path = 'IdentityGovernance/TermsOfUse/Agreements'
            Tag = @('All', 'Config', 'Governance')
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
                    Tag = @('All', 'Config', 'Governance')
                },
                @{
                    GraphUri = 'identityGovernance/entitlementManagement/connectedOrganizations/{id}/internalSponsors'
                    Path = 'InternalSponsors'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'Governance')
                }
            )    
        },            
        @{
            GraphUri = 'identityGovernance/entitlementManagement/settings'
            Path = 'IdentityGovernance/EntitlementManagement/Settings'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Governance')
        },
        @{
            GraphUri = 'AdministrativeUnits'
            Path = 'AdministrativeUnits'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'AdministrativeUnits')
            Children = @(
                @{
                    GraphUri = 'administrativeUnits/{id}/members'
                    Select = 'Id'
                    Path = 'Members'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'AdministrativeUnits')
                },
                @{
                    GraphUri = 'administrativeUnits/{id}/scopedRoleMembers'
                    Path = 'ScopedRoleMembers'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'AdministrativeUnits')
                },
                @{
                    GraphUri = 'administrativeUnits/{id}/extensions'
                    Path = 'Extensions'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'AdministrativeUnits')
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
            Tag = @('All', 'Config', 'Groups')
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