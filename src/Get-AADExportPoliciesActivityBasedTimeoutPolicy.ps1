<# 
 .Synopsis
 Represents a policy that can control the idle timeout for web sessions for applications that support activity-based timeout functionality. 

 .Description
  GET /policies/ActivityBasedTimeoutPolicy 
  https://docs.microsoft.com/en-us/graph/api/activitybasedtimeoutpolicy-list?view=graph-rest-1.0&tabs=http

 .Example
  Get-AADExportPoliciesActivityBasedTimeoutPolicy 
#>

Function Get-AADExportPoliciesActivityBasedTimeoutPolicy {
    Invoke-Graph 'policies/activityBasedTimeoutPolicies'
  }