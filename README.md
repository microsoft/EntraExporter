# Azure AD Exporter

The Azure AD Exporter is a PowerShell module that allows you to export your Azure AD and Azure AD B2C configuration settings to local .json files.

This module can be run as a nightly scheduled task or a DevOps component (Azure DevOps, GitHub, Jenkins) and the exported files can be version controlled in GIT or SharePoint.

This will provide tenant administrators with a historical view of all the settings in the tenant including the change history over the years.

Note: This project is not intended to be a backup or disaster recovery solution for Azure Active Directory.

## Exported settings include
* Users
* Groups
  * Dynamic and Assigned groups (incl. Members and Owners)
  * Group Settings
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
    * Azure AD Roles
    * Azure Resources
  * Terms of Use
* Application Proxy
  * Connectors and Connect Groups
  * Agents and Agent Groups
  * Published Resources
* Licences
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
  * Continouse Access Evaluation Policy
  * Identity Security Defaults Enforcement Policy
  * Permission Grant Policies
* Tenant Policies and Settings
  * Feature Rollout Policies
  * Certificate Based Auth Configuration
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


Note: This module exports all settings that are available through the Microsoft Graph API. Azure AD settings and objects that are not yet available in the Graph API are not included.

## Installing the module
```powershell
    Install-Module AzureADExporter
```

## Using the module

### Connecting to your tenant
```powershell
    Connect-AADExporter
```

### Exporting objects and settings

To export object and settings use the following command:

```powershell
    Invoke-AADExporter -Path 'C:\AzureADBackup\'
```

This will export the most common set of object and settings.

The following object and settings are not exported by default:
* B2C
* B2B
* Static Groups and group memberships
* Applications
* ServicePrincipals
* Users
* Priviledge Identity Management (built in roles, default roles settings, non permanent role assignement)

To export all the objects and settings supported (no filter applied):

```powershell
    Invoke-AADExporter -Path 'C:\AzureADBackup\' -All
```

To Select specific object and settings to export the ``-Type`` parameter can be used. The default type is "Config":

```powershell
    # export default all users as well as default objects and settings
    Invoke-AADExporter -Path 'C:\AzureADBackup\' -Type "Config","Users"
    # export applications only
    Invoke-AADExporter -Path 'C:\AzureADBackup\' -Type "Applications"
     # export B2C specific properties only
    Invoke-AADExporter -Path 'C:\AzureADBackup\' -Type "B2C"
    # export B2B properties along with AD properties
    Invoke-AADExporter -Path 'C:\AzureADBackup\' -Type "B2B","Config"
```

A filter can be applied to only export user and groups that are not synced from onprem (cloud users and groups):

```powershell
    Invoke-AADExporter -Path 'C:\AzureADBackup\' -CloudUsersOrGroupsOnly
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
