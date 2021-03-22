<# 
 .Synopsis
  Retrieve the properties of an identitySecurityDefaultsEnforcementPolicy object.

 .Description
  GET /policies/identitySecurityDefaultsEnforcementPolicy
  https://docs.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get

 .Example
  Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy
#>

Function Get-AADExportPoliciesIdentitySecurityDefaultsEnforcementPolicy {
  Invoke-Graph 'policies/identitySecurityDefaultsEnforcementPolicy'
}