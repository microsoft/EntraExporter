<#
.SYNOPSIS
    Connect the Azure AD Exporter module to Azure AD tenant.
.DESCRIPTION
    This command will connect Microsoft.Graph to your Azure AD tenant.
    You can also directly call Connect-MgGraph if you require other options to connect
.EXAMPLE
    PS C:\>Connect-AADExporter
    Connect to home tenant of authenticated user.
.EXAMPLE
    PS C:\>Connect-AADExporter -TenantId 3043-343434-343434
    Connect to a specific Tenant
#>
function Connect-AADExporter {
    param(
        [Parameter(Mandatory = $false)]
        [string] $TenantId = 'common'
    )    
    Connect-MgGraph -Scopes 'Directory.Read.All' -TenantId $TenantId
    Get-MgContext
}