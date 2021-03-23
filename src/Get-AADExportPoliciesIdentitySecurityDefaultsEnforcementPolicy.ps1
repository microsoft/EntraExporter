<# 
 .Synopsis
  Represents the Azure Active Directory security defaults policy. Security defaults contain preconfigured security settings that protect against common attacks.

 .Description
  GET /policies/identitySecurityDefaultsEnforcementPolicy
  https://docs.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get

 .Example
  Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy
#>

Function Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy {
  Invoke-Graph 'policies/identitySecurityDefaultsEnforcementPolicy'
}