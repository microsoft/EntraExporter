# Entra Exporter

[![PSGallery Version](https://img.shields.io/powershellgallery/v/EntraExporter.svg?style=flat&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/EntraExporter) [![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/EntraExporter.svg?style=flat&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/EntraExporter) [![PSGallery Platform](https://img.shields.io/powershellgallery/p/EntraExporter.svg?style=flat&label=PSGallery%20Platform)](https://www.powershellgallery.com/packages/EntraExporter)

The Entra Exporter is a PowerShell module that allows you to export your Entra and Azure AD B2C configuration settings to local .json files.

This module can be run as a nightly scheduled task or a DevOps component (Azure DevOps, GitHub, Jenkins) and the exported files can be version controlled in Git or SharePoint.

This will provide tenant administrators with a historical view of all the settings in the tenant including the change history over the years.

> [!IMPORTANT]
> The AzureADExporter module in the PowerShell Gallery is now deprecated. Please install the new **EntraExporter** module.

## Installing the module

```powershell
Install-Module EntraExporter
```

## Using the module

### Connecting and exporting your config

```powershell
Connect-EntraExporter
Export-Entra -Path 'C:\EntraBackup\'
```

While Connect-EntraExporter is available for convenience you can alternatively use Connect-MgGraph with the following scopes to authenticate.

```powershell
Connect-MgGraph -Scopes 'Directory.Read.All', 'Policy.Read.All', 'IdentityProvider.Read.All', 'Organization.Read.All', 'User.Read.All', 'EntitlementManagement.Read.All', 'UserAuthenticationMethod.Read.All', 'IdentityUserFlow.Read.All', 'APIConnectors.Read.All', 'AccessReview.Read.All', 'Agreement.Read.All', 'Policy.Read.PermissionGrant', 'PrivilegedAccess.Read.AzureResources', 'PrivilegedAccess.Read.AzureAD', 'Application.Read.All'
```

### Export options

To export object and settings use the following command:

```powershell
Export-Entra -Path 'C:\EntraBackup\'
```

This default method exports the most common set of objects and settings.

> [!NOTE]
> We recommend using PowerShell 7+ to create a consistent output. While PowerShell 5.1 can be used the output generated is not optimal.

The following objects and settings are not exported by default:

* B2C, B2B, Static Groups and group memberships, Applications, ServicePrincipals, Users, Privileged Identity Management (built in roles, default roles settings, non permanent role assignments)

Use the -All parameter to perform a full export:

```powershell
Export-Entra -Path 'C:\EntraBackup\' -All
```

The ``-Type`` parameter can be used to select specific objects and settings to export. The default type is "Config":

```powershell
# export default all users as well as default objects and settings
Export-Entra -Path 'C:\EntraBackup\' -Type "Config","Users"

# export applications only
Export-Entra -Path 'C:\EntraBackup\' -Type "Applications"

# export B2C specific properties only
Export-Entra -Path 'C:\EntraBackup\' -Type "B2C"

# export B2B properties along with AD properties
Export-Entra -Path 'C:\EntraBackup\' -Type "B2B","Config"
```

The currently valid types are: All (all elements), Config (default configuration), AccessReviews, ConditionalAccess, Users, Groups, Applications, ServicePrincipals, B2C, B2B, PIM, PIMAzure, PIMAAD, AppProxy, Organization, Domains, EntitlementManagement, Policies, AdministrativeUnits, SKUs, Identity, Roles, Governance

This list can also be retrieved via:

```powershell
(Get-Command Export-Entra | Select-Object -Expand Parameters)['Type'].Attributes.ValidValues
```

Additional filters can be applied:

* To exclude on-prem synced users from the export

```powershell
Export-Entra -Path 'C:\EntraBackup\' -All -CloudUsersAndGroupsOnly
```

> [!NOTE]
> This module exports all settings that are available through the Microsoft Graph API. Entra settings and objects that are not yet available in the Graph API are not included.

## Exported configuration includes

* Users
* Groups
  * Dynamic and Assigned groups (incl. Members and Owners)
  * Group Settings
* Devices
* External Identities
  * Authorization Policy
  * API Connectors
  * User Flows
* Roles and Administrators
* Administrative Units
* Applications
  * Enterprise Applications
  * App Registrations
  * Claims Mapping Policy
  * Extension Properties
  * Admin Consent Request Policy
  * Permission Grant Policies
  * Token Issuance Policies
  * Token Lifetime Policies
* Identity Governance
  * Entitlement Management
    * Access Packages
    * Catalogs
    * Connected Organizations
  * Access Reviews
  * Privileged Identity Management
    * Entra Roles
    * Azure Resources
  * Terms of Use
* Application Proxy
  * Connectors and Connect Groups
  * Agents and Agent Groups
  * Published Resources
* Licenses
* Connect sync settings
* Custom domain names
* Company branding
  * Profile Card Properties
* User settings
* Tenant Properties
  * Technical contacts
* Security
  * Conditional Access Policies
  * Named Locations
  * Authentication Methods Policies
  * Identity Security Defaults Enforcement Policy
  * Permission Grant Policies
* Tenant Policies and Settings
  * Feature Rollout Policies
  * Cross-tenant Access
  * Activity Based Timeout Policies
* Hybrid Authentication
  * Identity Providers
  * Home Realm Discovery Policies

* B2C Settings
  * B2C User Flows
    * Identity Providers
    * User Attribute Assignments
    * API Connector Configuration
    * Languages

## Integrate to Azure DevOps Pipeline

Exporting Entra settings to json files makes them useful to integrate with DevOps pipelines.

> **Note**:
> Delegated authentication will require a dedicated agent where the authentication has been pre-configured.

Below is a sample of exporting in two steps:

1. Export Entra to local json files
2. Update a git repository with the files

To export the configuration (replace variables with ``<>`` with the values suited to your situation):

```powershell
$tenantPath = './<tenant export path>'
$tenantId = '<tenant id>'
Write-Host 'git checkout main...'
git config --global core.longpaths true #needed for Windows
git checkout main

Write-Host 'Clean git folder...'
Remove-Item $tenantPath -Force -Recurse

Write-Host 'Installing modules...'
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
Install-Module EntraExporter -Scope CurrentUser -Force

Write-Host 'Connecting...'
Connect-EntraExporter -TenantId $tenantId

Write-Host 'Starting backup...'
Export-Entra $tenantPath -All
```

To update the git repository with the generated files:

```powershell
Write-Host 'Updating repo...'
git config user.email "<email>"
git config user.name "<name>"
git add -u
git add -A
git commit -m "ADO Update"
git push origin
```

BTW Here is a really good step by step guide from Ondrej Sebela that includes illustrations as well:

[How to easily backup your Azure environment using EntraExporter and Azure DevOps Pipeline](https://doitpsway.com/how-to-easily-backup-your-azure-environment-using-entraexporter-and-azure-devops-pipeline)

## FAQs

### Error 'Could not find a part of the path' when exported JSON file paths are longer than 260 characters

A workaround to this is to enable long paths via the Windows registry or a GPO setting. Run the following from an elevated PowerShell session and then close PowerShell before trying your export again:

```powershell
New-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
    -Name "LongPathsEnabled" `
    -Value 1 `
    -PropertyType DWORD `
    -Force
```

Credit: @shaunluttin via https://bigfont.ca/enable-long-paths-in-windows-with-powershell/ and https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=powershell.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
