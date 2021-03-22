<# 
 .Synopsis
  Represents settings that control the behavior of Azure AD entitlement management.

 .Description
  GET /identityGovernance/entitlementManagement/settings
  https://docs.microsoft.com/en-us/graph/api/entitlementmanagementsettings-get

 .Example
  Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy
#>

Function Get-AADExportIdentityGovernanceEntitlementManagementSettings {
  Invoke-Graph 'identityGovernance/entitlementManagement/settings'
}