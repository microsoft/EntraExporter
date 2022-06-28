$global:TenantID = $null
<#
.SYNOPSIS
    Connect the Azure AD Exporter module to Azure AD tenant.
.DESCRIPTION
    This command will connect Microsoft.Graph to your Azure AD tenant.
    You can also directly call Connect-MgGraph if you require other options to connect
.EXAMPLE
    PS C:\>Connect-AzureADExporter
    Connect to home tenant of authenticated user.
.EXAMPLE
    PS C:\>Connect-AzureADExporter -TenantId 3043-343434-343434
    Connect to a specific Tenant
#>
function Connect-AzureADExporter {
    param(
        [Parameter(Mandatory = $false)]
            [string] $TenantId = 'common',
        [Parameter(Mandatory=$false)]
            [ArgumentCompleter( {
                param ( $CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters )
                (Get-MgEnvironment).Name
            } )]
            [string]$Environment
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
        'PrivilegedAccess.Read.AzureAD'
    Get-MgContext
    $global:TenantID = (Get-MgContext).TenantId
}
