<#
 .Synopsis
  Gets the default export schema definition

 .Description
  Gets the default export schema definition. Defining the order in which elements are exported.

 .Example
  Get-EEDefaultSchema
#>

function Get-EEDefaultSchema  {
    $global:TenantID = (Get-MgContext).TenantId
    return  @(
        # Organization
        @{
            GraphUri = 'organization'
            Path = 'Organization/Organization.json'
            Tag = @('All', 'Config', 'Organization')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
        },
        @{
            GraphUri = 'organization/{0}/branding/localizations' -f $TenantID
            Path = 'Organization/Branding/Localizations.json'
            Tag = @('All', 'Config', 'Organization')
            DelegatedPermission = 'User.Read.All'
        },
        @{
            GraphUri = 'organization/{0}/certificateBasedAuthConfiguration' -f $TenantID
            Path = 'Organization/CertificateBasedAuthConfiguration.json'
            Tag = @('All', 'Config', 'Organization')
            DelegatedPermission = 'Organization.Read.All'
            ApplicationPermission = 'Organization.Read.All'
        },
        @{
            GraphUri = 'directory/onPremisesSynchronization/{0}' -f $TenantID
            Path = 'Directory/OnPremisesSynchronization.json'
            Tag = @('All', 'Config', 'Directory')
            DelegatedPermission = 'OnPremDirectorySynchronization.Read.All'
        },
        @{
            GraphUri = 'domains'
            Path = 'Domains'
            Tag = @('All', 'Config','Domains')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
        },
        @{
            GraphUri = 'identity/apiConnectors'
            Path = 'Identity/APIConnectors'
            ApiVersion = 'beta'
            IgnoreError = 'The feature self service sign up is not enabled for the tenant'
            Tag = @('All', 'Config', 'Identity')
            DelegatedPermission = 'APIConnectors.ReadWrite.All'
            ApplicationPermission = 'APIConnectors.ReadWrite.All'
        },
        @{
            GraphUri = 'identityProviders'
            Path = 'IdentityProviders'
            Tag = @('All', 'Config', 'Identity')
            DelegatedPermission = 'IdentityProvider.Read.All'
        },
        @{
            GraphUri = 'subscribedSkus'
            Path = 'SubscribedSkus'
            Tag = @('All', 'Config', 'SKUs')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
        },
        @{
            GraphUri = 'directoryRoles'
            Path = 'DirectoryRoles'
            Tag = @('All', 'Config', 'Roles')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
            Children = @(
                @{
                    GraphUri = 'directoryRoles/{id}/members'
                    Select = 'id, userPrincipalName, displayName'
                    Path = 'Members'
                    Tag = @('All', 'Config', 'Roles')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                }
                @{
                    GraphUri = 'directoryroles/{id}/scopedMembers'
                    Path = 'ScopedMembers'
                    Tag = @('All', 'Config', 'Roles')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                }
            )
        },

        # B2C
        @{
            GraphUri = 'identity/userFlows'
            Path = 'Identity/UserFlows'
            Tag = @('B2C')
            DelegatedPermission = 'IdentityUserFlow.Read.All'
            ApplicationPermission = 'IdentityUserFlow.Read.All'
        },
        @{
            GraphUri = 'identity/b2cUserFlows'
            Path = 'Identity/B2CUserFlows'
            Tag = @('B2C')
            DelegatedPermission = 'IdentityUserFlow.Read.All'
            ApplicationPermission = 'IdentityUserFlow.Read.All'
            Children = @(
                @{
                    GraphUri = 'identity/b2cUserFlows/{id}/identityProviders'
                    Path = 'IdentityProviders'
                    Tag = @('B2C')
                    DelegatedPermission = 'IdentityUserFlow.Read.All'
                    ApplicationPermission = 'IdentityUserFlow.Read.All'
                },
                @{
                    GraphUri = 'identity/b2cUserFlows/{id}/userAttributeAssignments'
                    QueryParameters = @{ '$expand' = 'userAttribute' }
                    Path = 'UserAttributeAssignments'
                    Tag = @('B2C')
                    DelegatedPermission = 'IdentityUserFlow.Read.All'
                    ApplicationPermission = 'IdentityUserFlow.Read.All'
                },
                @{
                    GraphUri = 'identity/b2cUserFlows/{id}/apiConnectorConfiguration'
                    QueryParameters = @{ '$expand' = 'postFederationSignup,postAttributeCollection' }
                    Path = 'ApiConnectorConfiguration'
                    Tag = @('B2C')
                    DelegatedPermission = 'IdentityUserFlow.Read.All'
                    ApplicationPermission = 'IdentityUserFlow.Read.All'
                },
                @{
                    GraphUri = 'identity/b2cUserFlows/{id}/languages'
                    Path = 'Languages'
                    Tag = @('B2C')
                    DelegatedPermission = 'IdentityUserFlow.Read.All'
                    ApplicationPermission = 'IdentityUserFlow.Read.All'
                }
            )
        },

        # B2B
        @{
            GraphUri = 'identity/userFlowAttributes'
            Path = 'Identity/UserFlowAttributes'
            ApiVersion = 'beta'
            Tag = @('Config', 'B2B', 'B2C')
            DelegatedPermission = 'IdentityUserFlow.Read.All'
            ApplicationPermission = 'IdentityUserFlow.Read.All'
            IgnoreError = 'The feature self service sign up is not enabled for the tenant'
        },
        @{
            GraphUri = 'identity/b2xUserFlows'
            Path = 'Identity/B2XUserFlows'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'B2B')
            DelegatedPermission = 'IdentityUserFlow.Read.All'
            ApplicationPermission = 'IdentityUserFlow.Read.All'
            Children = @(
                @{
                    GraphUri = 'identity/b2xUserFlows/{id}/identityProviders'
                    Path = 'IdentityProviders'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'B2B')
                    DelegatedPermission = 'IdentityUserFlow.Read.All'
                    ApplicationPermission = 'IdentityUserFlow.Read.All'
                },
                @{
                    GraphUri = 'identity/b2xUserFlows/{id}/userAttributeAssignments'
                    QueryParameters = @{ '$expand' = 'userAttribute' }
                    Path = 'AttributeAssignments'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'B2B')
                    DelegatedPermission = 'IdentityUserFlow.Read.All'
                    ApplicationPermission = 'IdentityUserFlow.Read.All'
                },
                @{
                    GraphUri = 'identity/b2xUserFlows/{id}/apiConnectorConfiguration'
                    QueryParameters = @{ '$expand' = 'postFederationSignup,postAttributeCollection' }
                    Path = 'APIConnectors'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'B2B')
                    DelegatedPermission = 'IdentityUserFlow.Read.All'
                    ApplicationPermission = 'IdentityUserFlow.Read.All'
                },
                @{
                    GraphUri = 'identity/b2xUserFlows/{id}/languages'
                    Path = 'Languages'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'B2B')
                    DelegatedPermission = 'IdentityUserFlow.Read.All'
                    ApplicationPermission = 'IdentityUserFlow.Read.All'
                }
            )
        },

        # Policies
        @{
            GraphUri = 'policies/identitySecurityDefaultsEnforcementPolicy'
            Path =  'Policies/IdentitySecurityDefaultsEnforcementPolicy'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/authorizationPolicy'
            Path = 'Policies/AuthorizationPolicy'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/featureRolloutPolicies'
            Path = 'Policies/FeatureRolloutPolicies'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Directory.ReadWrite.All'
        },
        @{
            GraphUri = 'policies/activityBasedTimeoutPolicies'
            Path = 'Policies/ActivityBasedTimeoutPolicy'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/homeRealmDiscoveryPolicies'
            Path = 'Policies/HomeRealmDiscoveryPolicy'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/claimsMappingPolicies'
            Path = 'Policies/ClaimsMappingPolicy'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/tokenIssuancePolicies'
            Path = 'Policies/TokenIssuancePolicy'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/tokenLifetimePolicies'
            Path = 'Policies/TokenLifetimePolicy'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/defaultAppManagementPolicy'
            Path = 'Policies/DefaultAppManagementPolicy'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/appManagementPolicies'
            Path = 'Policies/AppManagementPolicies'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/email'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/Email.json'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/FIDO2.json'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/MicrosoftAuthenticator.json'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/SMS.json'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/TemporaryAccessPass.json'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/softwareOath'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/SoftwareOath.json'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/voice'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/Voice.json'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/x509Certificate'
            Path = 'Policies/AuthenticationMethodsPolicy/AuthenticationMethodConfigurations/X509Certificate.json'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/adminConsentRequestPolicy'
            Path = 'Policies/AdminConsentRequestPolicy'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/permissionGrantPolicies'
            Path = 'Policies/PermissionGrantPolicies'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.PermissionGrant'
            ApplicationPermission = 'Policy.Read.PermissionGrant'
        },
        @{
            GraphUri = 'policies/externalIdentitiesPolicy'
            Path = 'Policies/ExternalIdentitiesPolicy'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/crossTenantAccessPolicy'
            Path = 'Policies/CrossTenantAccessPolicy'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/crossTenantAccessPolicy/default'
            Path = 'Policies/CrossTenantAccessPolicy/Default'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'policies/crossTenantAccessPolicy/partners'
            Path = 'Policies/CrossTenantAccessPolicy/Partners'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Policies')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'identity/customAuthenticationExtensions'
            Path = 'Identity/CustomAuthenticationExtensions'
            ApiVersion = 'beta'
            Tag = @('All', 'Config')
            DelegatedPermission = 'Application.Read.All'
            ApplicationPermission = 'Application.Read.All'
        },

        # Conditional Access
        #TIP export for PIM too, because of possible use of authentication context
        @{
            GraphUri = 'identity/conditionalAccess/policies'
            Path =  'Identity/Conditional/AccessPolicies'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'ConditionalAccess', 'PIM', 'PIMDirectoryRoles', 'PIMResources', 'PIMGroups')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'identity/conditionalAccess/namedLocations'
            Path =  'Identity/Conditional/NamedLocations'
            Tag = @('All', 'Config', 'ConditionalAccess')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        },
        @{
            GraphUri = 'identity/conditionalAccess/authenticationContextClassReferences'
            Path =  'Identity/Conditional/AuthenticationContexts'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'ConditionalAccess', 'PIM', 'PIMDirectoryRoles', 'PIMResources', 'PIMGroups')
            DelegatedPermission = 'Policy.Read.All'
            ApplicationPermission = 'Policy.Read.All'
        }

        # Identity Governance,
        @{
            GraphUri = 'identityGovernance/entitlementManagement/accessPackages'
            Path = 'IdentityGovernance/EntitlementManagement/AccessPackages'
            ApiVersion = 'beta'
            Tag = @('All', 'Governance', 'EntitlementManagement')
            DelegatedPermission = 'EntitlementManagement.Read.All'
            ApplicationPermission = 'EntitlementManagement.Read.All'
            Children = @(
                @{
                    Command = 'Get-AccessPackageAssignmentPolicies'
                    Path = 'AssignmentPolicies'
                    Tag = @('All', 'Governance', 'EntitlementManagement')
                    DelegatedPermission = 'EntitlementManagement.Read.All'
                    ApplicationPermission = 'EntitlementManagement.Read.All'
                },
                @{
                    Command = 'Get-AccessPackageAssignments'
                    Path = 'Assignments'
                    Tag = @('All', 'Governance', 'EntitlementManagement')
                    DelegatedPermission = 'EntitlementManagement.Read.All'
                    ApplicationPermission = 'EntitlementManagement.Read.All'
                },
                @{
                    Command = 'Get-AccessPackageResourceScopes'
                    Path = 'ResourceScopes'
                    Tag = @('All', 'Governance', 'EntitlementManagement')
                    DelegatedPermission = 'EntitlementManagement.Read.All'
                    ApplicationPermission = 'EntitlementManagement.Read.All'
                }
            )
        },
        @{
            GraphUri = 'identityGovernance/accessReviews/definitions'
            Path = 'IdentityGovernance/AccessReviews'
            ApiVersion = 'beta'
            Tag = @('All', 'AccessReviews', 'Governance')
            DelegatedPermission = 'AccessReview.Read.All'
            ApplicationPermission = 'AccessReview.Read.All'
            Children = @(
                @{
                    GraphUri = 'identityGovernance/accessReviews/definitions/{id}/instances'
                    Path = ''
                    Tag = @('All', 'AccessReviews', 'Governance')
                    DelegatedPermission = 'AccessReview.Read.All'
                    ApplicationPermission = 'AccessReview.Read.All'
                    Children = @(
                        @{
                            GraphUri = 'identityGovernance/accessReviews/definitions/{id}/instances/{id}/contactedReviewers'
                            Path = 'Reviewers'
                            ApiVersion = 'beta'
                            Tag = @('All', 'AccessReviews', 'Governance')
                            DelegatedPermission = 'AccessReview.Read.All'
                            ApplicationPermission = 'AccessReview.Read.All'
                        }
                    )
                }
            )
        },
        @{
            GraphUri = 'identityGovernance/termsOfUse/agreements'
            Path = 'IdentityGovernance/TermsOfUse/Agreements'
            Tag = @('All', 'Config', 'Governance')
            DelegatedPermission = 'Agreement.Read.All'
        },
        @{
            GraphUri = 'identityGovernance/entitlementManagement/connectedOrganizations'
            Path = 'IdentityGovernance/EntitlementManagement/ConnectedOrganizations'
            ApiVersion = 'beta'
            Tag = @('All', 'Config')
            DelegatedPermission = 'EntitlementManagement.Read.All'
            ApplicationPermission = 'EntitlementManagement.Read.All'
            Children = @(
                @{
                    GraphUri = 'identityGovernance/entitlementManagement/connectedOrganizations/{id}/externalSponsors'
                    Path = 'ExternalSponsors'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'Governance')
                    DelegatedPermission = 'EntitlementManagement.Read.All'
                    ApplicationPermission = 'EntitlementManagement.Read.All'
                },
                @{
                    GraphUri = 'identityGovernance/entitlementManagement/connectedOrganizations/{id}/internalSponsors'
                    Path = 'InternalSponsors'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'Governance')
                    DelegatedPermission = 'EntitlementManagement.Read.All'
                    ApplicationPermission = 'EntitlementManagement.Read.All'
                }
            )
        },
        @{
            GraphUri = 'identityGovernance/entitlementManagement/settings'
            Path = 'IdentityGovernance/EntitlementManagement/Settings'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Governance')
            DelegatedPermission = 'EntitlementManagement.Read.All'
            ApplicationPermission = 'EntitlementManagement.Read.All'
        },
        @{
            GraphUri = 'AdministrativeUnits'
            Path = 'AdministrativeUnits'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'AdministrativeUnits')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
            Children = @(
                @{
                    GraphUri = 'administrativeUnits/{id}/members'
                    Select = 'Id'
                    Path = 'Members'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'AdministrativeUnits')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'administrativeUnits/{id}/scopedRoleMembers'
                    Path = 'ScopedRoleMembers'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'AdministrativeUnits')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'administrativeUnits/{id}/extensions'
                    Path = 'Extensions'
                    ApiVersion = 'beta'
                    Tag = @('All', 'Config', 'AdministrativeUnits')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                }
            )
        },

        # PIM Directory Roles
        @{
            Path                  = 'PIM/DirectoryRoles'
            Command                = 'Get-AzurePIMDirectoryRoles'
            Tag                   = @('All', 'PIM', 'PIMDirectoryRoles')
            DelegatedPermission   = 'RoleEligibilitySchedule.Read.Directory'
            ApplicationPermission = 'RoleEligibilitySchedule.Read.Directory'
        },

        # PIM Groups
        @{
            Path                  = 'PIM/Groups'
            Command                = 'Get-AzurePIMGroups'
            Tag                   = @('All', 'PIM','PIMGroups')
            DelegatedPermission   = 'PrivilegedEligibilitySchedule.Read.AzureADGroup'
            ApplicationPermission = 'PrivilegedEligibilitySchedule.Read.AzureADGroup'
        },

        # PIM Resources
        @{
            Path                  = 'PIM/Resources'
            Command                = 'Get-AzurePIMResources'
            Tag                   = @('All','PIM', 'PIMResources')
            DelegatedPermission   = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
            # RBAC role "Management Group Reader" assigned at "Tenant Root Group" level is required to be able to read Management Groups
            # requires connection via Connect-AzAccount
        }

        #Application Proxy
        @{
            GraphUri = 'onPremisesPublishingProfiles/provisioning'
            QueryParameters = @{ '$expand' = 'publishedResources,agents,agentGroups' }
            Path = 'OnPremisesPublishingProfiles/Provisioning.json'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'AppProxy')
            DelegatedPermission = 'OnPremisesPublishingProfiles.ReadWrite.All'
        },
        @{
            GraphUri = 'onPremisesPublishingProfiles/provisioning/publishedResources'
            QueryParameters = @{ '$expand' = 'agentGroups' }
            Path = 'OnPremisesPublishingProfiles/Provisioning/PublishedResources'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'AppProxy')
            DelegatedPermission = 'OnPremisesPublishingProfiles.ReadWrite.All'
        },
        @{
            GraphUri = 'onPremisesPublishingProfiles/provisioning/agentGroups'
            QueryParameters = @{ '$expand' = 'agents,publishedResources' }
            Path = 'OnPremisesPublishingProfiles/Provisioning/AgentGroups'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'AppProxy')
            DelegatedPermission = 'OnPremisesPublishingProfiles.ReadWrite.All'
        },
        @{
            GraphUri = 'onPremisesPublishingProfiles/provisioning/agents'
            QueryParameters = @{ '$expand' = 'agentGroups' }
            Path = 'OnPremisesPublishingProfiles/Provisioning/Agents'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'AppProxy')
            DelegatedPermission = 'OnPremisesPublishingProfiles.ReadWrite.All'
        },
        @{
            GraphUri = 'onPremisesPublishingProfiles/applicationProxy/connectors'
            Path = 'OnPremisesPublishingProfiles/ApplicationProxy/Connectors'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'AppProxy')
            DelegatedPermission = 'Directory.ReadWrite.All'
        },
        @{
            GraphUri = 'onPremisesPublishingProfiles/applicationProxy/connectorGroups'
            Path = 'OnPremisesPublishingProfiles/ApplicationProxy/ConnectorGroups'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'AppProxy')
            DelegatedPermission = 'Directory.ReadWrite.All'
            Children = @(
                @{
                    GraphUri = 'onPremisesPublishingProfiles/applicationProxy/connectorGroups/{id}/applications'
                    Path = 'Applications'
                    ApiVersion = 'beta'
                    IgnoreError = 'ApplicationsForGroup_NotFound'
                    Tag = @('All', 'Config', 'AppProxy')
                    DelegatedPermission = 'Directory.ReadWrite.All'
                },
                @{
                    GraphUri = 'onPremisesPublishingProfiles/applicationProxy/connectorGroups/{id}/members'
                    Path = 'Members'
                    ApiVersion = 'beta'
                    IgnoreError = 'ConnectorGroup_NotFound'
                    Tag = @('All', 'Config', 'AppProxy')
                    DelegatedPermission = 'Directory.ReadWrite.All'
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
            QueryParameters = @{ '$count' = 'true'; '$expand' = 'extensions' }
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Groups')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
            Children = @(
                @{
                    GraphUri =  'groups/{id}/owners'
                    Select = 'id, userPrincipalName, displayName'
                    Path = 'Owners'
                    Tag = @('All', 'Config', 'Groups')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                }
            )
        },
        @{
            GraphUri = 'groups'
            Filter = "not(groupTypes/any(c:c eq 'DynamicMembership'))"
            Path = 'Groups'
            QueryParameters = @{ '$count' = 'true'; '$expand' = 'extensions' }
            ApiVersion = 'beta'
            Tag = @('All', 'Groups')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
            Children = @(
                @{
                    GraphUri =  'groups/{id}/owners'
                    Select = 'id, userPrincipalName, displayName'
                    Path = 'Owners'
                    Tag = @('All', 'Config', 'Groups')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'groups/{id}/members'
                    Select = 'id, userPrincipalName, displayName'
                    Path = 'Members'
                    Tag = @('All', 'Groups')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                }
            )
        },
        @{
            GraphUri = 'groupSettings'
            Path = 'GroupSettings'
            Tag = @('All', 'Config', 'Groups')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
        },

        # Applications
        @{
            GraphUri = 'applications'
            Path = 'Applications'
            Tag = @('All', 'Applications')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
            Children = @(
                @{
                    GraphUri = 'applications/{id}/extensionProperties'
                    Path = 'ExtensionProperties'
                    Tag = @('All', 'Applications')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'applications/{id}/owners'
                    Select = 'id, userPrincipalName, displayName'
                    Path = 'Owners'
                    Tag = @('All', 'Applications')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'applications/{id}/tokenIssuancePolicies'
                    Path = 'TokenIssuancePolicies'
                    Tag = @('All', 'Applications')
                    DelegatedPermission = 'Policy.Read.All'
                    ApplicationPermission = 'Policy.Read.All','Application.ReadWrite.All'
                },
                @{
                    GraphUri = 'applications/{id}/tokenLifetimePolicies'
                    Path = 'TokenLifetimePolicies'
                    Tag = @('All', 'Applications')
                    DelegatedPermission = 'Policy.Read.All'
                    ApplicationPermission = 'Policy.Read.All','Application.ReadWrite.All'
                },
                @{
                    GraphUri = "applications/{id}/appManagementPolicies"
                    Path = 'AppManagementPolicies'
                    Tag = @('All', 'Applications')
                    DelegatedPermission = 'Policy.Read.All'
                    ApplicationPermission = 'Policy.Read.All','Application.ReadWrite.All'
                }
            )
        },

        # Service Principals
        @{
            GraphUri = 'servicePrincipals'
            Path = 'ServicePrincipals'
            Tag = @('All', 'ServicePrincipals')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
            Children = @(
                @{
                    GraphUri = 'servicePrincipals/{id}/appRoleAssignments'
                    Path = 'AppRoleAssignments'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'servicePrincipals/{id}/appRoleAssignedTo'
                    Path = 'AppRoleAssignedTo'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'servicePrincipals/{id}/oauth2PermissionGrants'
                    Path = 'Oauth2PermissionGrants'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'servicePrincipals/{id}/delegatedPermissionClassifications'
                    Path = 'DelegatedPermissionClassifications'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'servicePrincipals/{id}/owners'
                    Select = 'id, userPrincipalName, displayName'
                    Path = 'Owners'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Directory.Read.All'
                    ApplicationPermission = 'Directory.Read.All'
                },
                @{
                    GraphUri = 'servicePrincipals/{id}/claimsMappingPolicies'
                    Path = 'ClaimsMappingPolicies'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Policy.Read.All'
                    ApplicationPermission = 'Policy.Read.All','Application.ReadWrite.All'
                },
                @{
                    GraphUri = 'servicePrincipals/{id}/homeRealmDiscoveryPolicies'
                    Path = 'HomeRealmDiscoveryPolicies'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Policy.Read.All'
                    ApplicationPermission = 'Policy.Read.All','Application.ReadWrite.All'
                },
                @{
                    GraphUri = 'servicePrincipals/{id}/tokenIssuancePolicies'
                    Path = 'TokenIssuancePolicies'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Policy.Read.All'
                    ApplicationPermission = 'Policy.Read.All','Application.ReadWrite.All'
                },
                @{
                    GraphUri = 'servicePrincipals/{id}/tokenLifetimePolicies'
                    Path = 'TokenLifetimePolicies'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Policy.Read.All'
                    ApplicationPermission = 'Policy.Read.All','Application.ReadWrite.All'
                },
                @{
                    GraphUri = 'servicePrincipals/{id}/appManagementPolicies'
                    Path = 'AppManagementPolicies'
                    Tag = @('All', 'ServicePrincipals')
                    DelegatedPermission = 'Policy.Read.All'
                    ApplicationPermission = 'Policy.Read.All','Application.ReadWrite.All'
                }
            )
        },

        # Users
        # Todo look at app roles assignments
        @{
            GraphUri = 'users'
            Path = 'Users'
            Filter = $null
            QueryParameters = @{ '$count' = 'true'; '$expand' = "extensions" }
            ApiVersion = 'beta'
            Tag = @('All', 'Users')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
        },

        # Devices
        @{
            GraphUri = 'devices'
            Path = 'Devices'
            Filter = $null
            ApiVersion = 'beta'
            Tag = @('All', 'Devices')
            DelegatedPermission = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
        },
        # Teams
        @{
            GraphUri = 'teamwork'
            Path = 'Admin/Teams/settings.json'
            Filter = $null
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Teams')
            DelegatedPermission = 'Teamwork.Read.All'
            ApplicationPermission = 'Teamwork.Read.All'
        },
        # Sharepoint
        @{
            GraphUri = 'admin/sharepoint/settings'
            Path = 'Admin/Sharepoint/settings.json'
            Filter = $null
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'Sharepoint')
            DelegatedPermission = 'SharePointTenantSettings.Read.All'
            ApplicationPermission = 'SharePointTenantSettings.Read.All'
        },
        # RoleManagement - Directory Role Definitions
        @{
            GraphUri = 'roleManagement/directory/roleDefinitions'
            Path = 'RoleManagement/Directory/RoleDefinitions'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'DirectoryRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'             
        },
        # RoleManagement - Directory Role Assignments
        @{
            GraphUri = 'roleManagement/directory/roleAssignments'
            Path = 'RoleManagement/Directory/RoleAssignments'
            QueryParameters = @{ expand = 'principal' }
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'DirectoryRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'             
        }   
        # RoleManagement - Exchange Role Definitions
        @{
            GraphUri = 'roleManagement/exchange/roleDefinitions'
            Path = 'RoleManagement/Exchange/RoleDefinitions'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'ExchangeRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'             
        },
        # RoleManagement - Exchange Role Assignments
        @{
            GraphUri = 'roleManagement/exchange/roleAssignments'
            Path = 'RoleManagement/Exchange/RoleAssignments'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'ExchangeRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'            
        },
        # RoleManagement - Intune Role Definitions
        @{
            GraphUri = 'roleManagement/deviceManagement/roleDefinitions'
            Path = 'RoleManagement/DeviceManagement/RoleDefinitions'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'IntuneRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'             
        },
        # RoleManagement - Intune Role Assignments
        @{
            GraphUri = 'roleManagement/deviceManagement/roleAssignments'
            Path = 'RoleManagement/DeviceManagement/RoleAssignments'
            QueryParameters = @{ expand = 'principals' }
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'IntuneRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'            
        } 
        # RoleManagement - CloudPC Role Definitions
        @{
            GraphUri = 'roleManagement/cloudPC/roleDefinitions'
            Path = 'RoleManagement/CloudPC/RoleDefinitions'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'CloudPCRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'             
        },
        # RoleManagement - CloudPC Role Assignments
        @{
            GraphUri = 'roleManagement/cloudPC/roleAssignments'
            Path = 'RoleManagement/CloudPC/RoleAssignments'
            QueryParameters = @{ expand = 'principals' }
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'CloudPCRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'            
        } 
        # RoleManagement - Entitlement Management Role Definitions
        @{
            GraphUri = 'roleManagement/entitlementManagement/roleDefinitions'
            Path = 'RoleManagement/EntitlementManagement/RoleDefinitions'
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'EntitlementManagementRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'             
        },
        # RoleManagement - Entitlement Management Role Assignments
        @{
            GraphUri = 'roleManagement/entitlementManagement/roleAssignments'
            Path = 'RoleManagement/EntitlementManagement/RoleAssignments'
            QueryParameters = @{ expand = 'principal' }
            ApiVersion = 'beta'
            Tag = @('All', 'Config', 'RoleManagement', 'EntitlementManagementRoles')
            DelegatedPermission = 'RoleManagement.Read.All'
            ApplicationPermission = 'RoleManagement.Read.All'            
        },
        # Reports - Users Registered By Feature
        @{
            GraphUri = 'reports/authenticationMethods/microsoft.graph.usersRegisteredByFeature()'
            Path = 'Reports/AuthenticationMethods/UsersRegisteredByFeature/report.json'
            ApiVersion = 'beta'
            Tag = @('All', 'Reports', 'UsersRegisteredByFeatureReport')
            DelegatedPermission = 'AuditLog.Read.All'            
        },
        
        # Permanent IAM role assignments
        @{
            Path                  = 'IAM'
            Filter                = $null
            Command                = 'Get-AzureResourceIAMData'
            Tag                   = @('All', 'IAM')
            DelegatedPermission   = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
            # requires connection via Connect-AzAccount
        },

        # Access Policies
        @{
            Path                  = 'AccessPolicies'
            Command                = 'Get-AzureResourceAccessPolicies'
            Tag                   = @('All', 'AccessPolicies')
            DelegatedPermission   = 'Directory.Read.All'
            ApplicationPermission = 'Directory.Read.All'
            # requires connection via Connect-AzAccount
            # requires 'Reader' role on 'Tenant Root Group' level (or the levels you want to export) to be able to read subscriptions and their resources!
        }
    )
}
