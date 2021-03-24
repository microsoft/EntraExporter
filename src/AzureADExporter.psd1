@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'AzureADExporter.psm1'
    
    # Version number of this module.
    ModuleVersion = '1.0'
    
    # Supported PSEditions
    CompatiblePSEditions = 'Core','Desktop'
    
    # ID used to uniquely identify this module
    GUID = '90d1b990-5858-40f7-bbec-bfad5bda9359'
    
    # Author of this module
    Author = 'Microsoft Identity'
    
    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'
    
    # Copyright statement for this module
    Copyright = 'Microsoft Corporation. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'This module exports all the Azure AD objects and Identity related settings in your tenant.'
    
    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'
    
    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''
    
    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''
    
    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''
    
    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # CLRVersion = ''
    
    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''
    
    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; Guid = '883916f2-9184-46ee-b1f8-b6a2fb784cee'; ModuleVersion = '1.1.0' }
    )
    
    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()
    
    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()
    
    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()
    
    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        'internal\Invoke-Graph.ps1'
        'internal\Get-ObjectProperty.ps1'
        'internal\ConvertFrom-QueryString.ps1'
        'internal\ConvertTo-QueryString.ps1'        
        'Connect-AADExporter.ps1'
        'Invoke-AADExporter.ps1'
        'Get-AADExportAPIConnectors.ps1'
        'Get-AADExportOrganization.ps1'
        'Get-AADExportSubscribedSkus.ps1'
        'Get-AADExportOrganizationBranding.ps1'
        'Get-AADExportConditionalAccessPolicies.ps1'
        'Get-AADExportUserFlows.ps1'
        'Get-AADExportUserFlowsB2C.ps1'
        'Get-AADExportUserFlowAttributes.ps1'
        'Get-AADExportDomains.ps1'
        'Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy.ps1'
        'Get-AADExportPoliciesAuthorizationPolicy.ps1'
        'Get-AADExportPoliciesHomeRealmDiscoveryPolicy.ps1'
        'Get-AADExportPoliciesClaimsMappingPolicy.ps1'
        'Get-AADExportPoliciesTokenIssuancePolicy.ps1'
        'Get-AADExportPoliciesTokenLifetimePolicy.ps1'
        'Get-AADExportIdentityProviders.ps1'
        'Get-AADExportCertificateBasedAuthConfiguration.ps1'
        'Get-AADExportOrganizationSettings.ps1'
        'Get-AADExportAuthenticationMethodPolicyEmail.ps1'
        'Get-AADExportAuthenticationMethodPolicyFIDO2.ps1'
        'Get-AADExportAuthenticationMethodPolicyMicrosoftAuthenticator.ps1'
        'Get-AADExportAuthenticationMethodPolicySMS.ps1'
        'Get-AADExportAuthenticationMethodPolicyTemporaryAccessPass.ps1'
        'Get-AADExportPoliciesAdminConsentRequestPolicy.ps1'
        'Get-AADExportIdentityGovernanceEntitlementManagementSettings.ps1'
        'Get-AADExportUsers.ps1'
        'Get-AADExportAuthenticationMethodFIDO2.ps1'
        'Get-AADExportAuthenticationMethodMicrosoftAuthenticator.ps1'
        'Get-AADExportAuthenticationMethodWindowsHelloForBusiness.ps1'
        'Get-AADExportAuthenticationMethodTemporaryAccessPass.ps1'
        'Get-AADExportAuthenticationMethodPhone.ps1'
        'Get-AADExportAuthenticationMethodEmail.ps1'
        'Get-AADExportAuthenticationMethodPassword.ps1'
        'Get-AADExportPoliciesActivityBasedTimeoutPolicy.ps1'
        'Get-AADExportGroups.ps1'
        'Get-AADExportGroupMembers.ps1'
        'Get-AADExportGroupOwners.ps1'
        'Get-AADExportGroupSettings.ps1'
        'Get-AADExportApplications.ps1'
        'Get-AADExportBusinessFlowTemplates.ps1'
        'Get-AADExportAccessReviews.ps1'
        'Get-AADExportConnectedOrganizations.ps1'
    )
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Connect-AADExporter'
        'Invoke-AADExporter'
        'Get-AADExportAPIConnectors'
        'Get-AADExportOrganization'
        'Get-AADExportSubscribedSkus'
        'Get-AADExportOrganizationBranding'
        'Get-AADExportConditionalAccessPolicies'
        'Get-AADExportUserFlows'
        'Get-AADExportUserFlowsB2C'
        'Get-AADExportUserFlowAttributes'
        'Get-AADExportDomains'
        'Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy'
        'Get-AADExportPoliciesAuthorizationPolicy'
        'Get-AADExportPoliciesHomeRealmDiscoveryPolicy'
        'Get-AADExportPoliciesClaimsMappingPolicy'
        'Get-AADExportPoliciesTokenLifetimePolicy'
        'Get-AADExportPoliciesTokenIssuancePolicy'
        'Get-AADExportIdentityProviders'
        'Get-AADExportCertificateBasedAuthConfiguration'
        'Get-AADExportOrganizationSettings'
        'Get-AADExportAuthenticationMethodPolicyEmail'
        'Get-AADExportAuthenticationMethodPolicyFIDO2'
        'Get-AADExportAuthenticationMethodPolicyMicrosoftAuthenticator'
        'Get-AADExportAuthenticationMethodPolicySMS'
        'Get-AADExportAuthenticationMethodPolicyTemporaryAccessPass'
        'Get-AADExportPoliciesAdminConsentRequestPolicy'
        'Get-AADExportIdentityGovernanceEntitlementManagementSettings'
        'Get-AADExportUsers'
        'Get-AADExportAuthenticationMethodFIDO2'
        'Get-AADExportAuthenticationMethodMicrosoftAuthenticator'
        'Get-AADExportAuthenticationMethodWindowsHelloForBusiness'
        'Get-AADExportAuthenticationMethodTemporaryAccessPass'
        'Get-AADExportAuthenticationMethodPhone'
        'Get-AADExportAuthenticationMethodEmail'
        'Get-AADExportAuthenticationMethodPassword'
        'Get-AADExportPoliciesActivityBasedTimeoutPolicy'
        'Get-AADExportGroups'
        'Get-AADExportGroupMembers'
        'Get-AADExportGroupOwners'
        'Get-AADExportGroupSettings'
        'Get-AADExportApplications'
        'Get-AADExportBusinessFlowTemplates'
        'Get-AADExportAccessReviews'
        'Get-AADExportConnectedOrganizations'
    )
    
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()
    
    # DSC resources to export from this module
    # DscResourcesToExport = @()
    
    # List of all modules packaged with this module
    # ModuleList = @()
    
    # List of all files packaged with this module
    # FileList = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
    
        PSData = @{
    
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = 'Microsoft', 'Identity', 'Azure', 'AzureActiveDirectory', 'AzureAD', 'AAD', 'PSEdition_Desktop', 'Windows', 'Export', 'Backup', 'DR'
    
            # A URL to the license for this module.
            LicenseUri = 'https://raw.githubusercontent.com/merill/azureadexporter/main/LICENSE'
    
            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/merill/azureadexporter'
    
            # A URL to an icon representing this module.
            # IconUri = ''
    
            # ReleaseNotes of this module
            # ReleaseNotes = ''
    
        } # End of PSData hashtable
    
    } # End of PrivateData hashtable
    
    # HelpInfo URI of this module
    # HelpInfoURI = ''
    
    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
    
    }
    
    