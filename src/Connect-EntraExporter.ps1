$global:TenantID = $null
<#
.SYNOPSIS
    Connect the Entra Exporter module to the Entra tenant.
.DESCRIPTION
    This command will connect Microsoft.Graph to your Entra tenant.
    You can also directly call Connect-MgGraph if you require other options to connect

    Use the following scopes when authenticating with Connect-MgGraph.

    Connect-MgGraph -Scopes 'Directory.Read.All', 'Policy.Read.All', 'IdentityProvider.Read.All', 'Organization.Read.All', 'User.Read.All', 'EntitlementManagement.Read.All', 'UserAuthenticationMethod.Read.All', 'IdentityUserFlow.Read.All', 'APIConnectors.Read.All', 'AccessReview.Read.All', 'Agreement.Read.All', 'Policy.Read.PermissionGrant', 'PrivilegedAccess.Read.AzureResources', 'PrivilegedAccess.Read.AzureAD', 'Application.Read.All'

.EXAMPLE
    PS C:\>Connect-EntraExporter
    Connect to home tenant of authenticated user.
.EXAMPLE
    PS C:\>Connect-EntraExporter -TenantId 3043-343434-343434
    Connect to a specific Tenant
#>
function Connect-EntraExporter {
    param(
        [Parameter(Mandatory = $false)]
            [string] $TenantId = 'common',
        [Parameter(Mandatory=$false)]
            [ArgumentCompleter( {
                param ( $CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters )
                (Get-MgEnvironment).Name
            } )]
            [string]$Environment = 'Global'
    )
    Connect-MgGraph -TenantId $TenantId -Environment $Environment -Scopes 'Directory.Read.All',
        'Policy.Read.All',
        'IdentityProvider.Read.All',
        'Organization.Read.All',
        'User.Read.All',
        'EntitlementManagement.Read.All',
        'UserAuthenticationMethod.Read.All',
        'IdentityUserFlow.Read.All',
        'APIConnectors.Read.All',
        'AccessReview.Read.All',
        'Agreement.Read.All',
        'Policy.Read.PermissionGrant',
        'PrivilegedAccess.Read.AzureResources',
        'PrivilegedAccess.Read.AzureAD',
        'Application.Read.All',
        'OnPremDirectorySynchronization.Read.All'
    Get-MgContext
    $global:TenantID = (Get-MgContext).TenantId
}
