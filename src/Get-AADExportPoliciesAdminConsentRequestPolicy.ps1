<# 
 .Synopsis
  Specifies the policy by which consent requests are created and managed for the entire tenant.

 .Description
  GET /policies/adminConsentRequestPolicy
  https://docs.microsoft.com/en-us/graph/api/adminconsentrequestpolicy-get

 .Example
  Get-AADExportPoliciesAdminConsentRequestPolicy
#>

Function Get-AADExportPoliciesAdminConsentRequestPolicy {
  Invoke-Graph 'policies/adminConsentRequestPolicy'
}