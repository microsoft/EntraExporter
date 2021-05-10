<# 
 .Synopsis
  Exports the Azure AD Configuration and settings for a tenant
 .Description
  This cmdlet reads the configuration information from the target Azure AD Tenant and produces the output files 
  in a target directory

 .PARAMETER OutputDirectory
    Specifies the directory path where the output files will be generated.

.PARAMETER Type
    Specifies the type of objects to export. Default to Config which exports the key configuration settings of the tenant.

.PARAMETER All
    If specified performs a full export of all objects and configuration in the tenant.

.EXAMPLE
   .\Export-AzureAD -Path 'c:\temp\contoso'

   Runs a default export and includes the key tenant configuration settings. Does not include large data collections such as Users, Groups, Applications, Service Principals, etc.
.EXAMPLE
   .\Export-AzureAD -Path 'c:\temp\contoso' -All
   
   Runs a full export of all objects and configuration settings.

.EXAMPLE
   .\Export-AzureAD -Path 'c:\temp\contoso' -Type ConditionalAccess, AppProxy

   Runs an export that includes just the Conditional Access and Application Proxy settings.

.EXAMPLE
   .\Export-AzureAD -Path 'c:\temp\contoso' -Type B2C

   Runs an export of all B2C settings.
#>

Function Export-AzureAD {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]$Path,        
        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Config', 'AccessReviews', 'ConditionalAccess', 'Users', 'Groups', 'Applications', 'ServicePrincipals','B2C','B2B','PIM','PIMAzure','PIMAAD', 'AppProxy', 'Organization', 'Domains', 'EntitlementManagement', 'Policies', 'AdministrativeUnits')]
        [String[]]$Type = 'Config',
        [Parameter(Mandatory = $false)]
        [object]$ExportSchema,
        [Parameter(Mandatory = $false)]
        [string[]]$Parents,
        [switch]
        $All,
        [switch]
        $CloudUsersAndGroupsOnly,
        [switch]
        $AllGroups
    )

    if ($null -eq (Get-MgContext)) {
        Write-Error "No active connection. Run Connect-AzureADExporter to sign in and then retry."
        exit
    }
    if($All) {$Type = @('All')}
    $global:TenantID = (Get-MgContext).TenantId
    $global:Type = $Type #Used in places like Groups where Config flag will limit the resultset to just dynamic groups.

    if (!$ExportSchema) {
        $ExportSchema = Get-AADExportDefaultSchema
    }
    

    # aditional filters
    foreach ($entry in $ExportSchema) {
        $graphUri = Get-ObjectProperty $entry "GraphUri"
        # filter out synced users or groups
        if ($CloudUsersAndGroupsOnly -and ($graphUri -in "users","groups")) {
            $entry.Filter = "onPremisesSyncEnabled ne true"
        }
        # get all groups
        if (($All -or $AllGroups) -and ($graphUri -eq "groups")) {
            $entry.Filter = $null
        }
        # get all PIM elements
        if ($All -and ($graphUri -in "privilegedAccess/aadroles/resources","privilegedAccess/azureResources/resources")) {
            $entry.Fitler = $null
        }
    }

    foreach ($item in $ExportSchema) {
        $typeMatch = Compare-Object $item.Tag $Type -ExcludeDifferent -IncludeEqual
        $hasParents = $Parents -and $Parents.Count -gt 0
        if( ($typeMatch)) {
            $outputFileName = Join-Path -Path $Path -ChildPath $item.Path

            $spacer = ''
            if($hasParents) { $spacer = ''.PadRight($Parents.Count + 3, ' ') + $Parents[$Parents.Count-1] }
            
            Write-Host "$spacer $($item.Path)"

            $command = Get-ObjectProperty $item 'Command'
            $graphUri = Get-ObjectProperty $item 'GraphUri'
            $apiVersion = Get-ObjectProperty $item 'ApiVersion'
            $ignoreError = Get-ObjectProperty $item 'IgnoreError'
            if (!$apiVersion) { $apiVersion = 'v1.0' }
            $resultItems = $null
            if($command) {
                if ($hasParents){ $command += " -Parents $Parents" }
                $resultItems = Invoke-Expression -Command $command
            }
            else {
                if ($hasParents){ $graphUri = $graphUri -replace '{id}', $Parents[$Parents.Count-1] }
                try {
                    $resultItems = Invoke-Graph $graphUri -Filter (Get-ObjectProperty $item 'Filter') -Select (Get-ObjectProperty $item 'Select') -QueryParameters (Get-ObjectProperty $item 'QueryParameters') -ApiVersion $apiVersion
                }
                catch {
                    $e = $_.ErrorDetails.Message
                    if($e.Contains($ignoreError) -or $e.Contains('Encountered an internal server error')){
                        Write-Debug $_
                    }
                    else {
                        Write-Error $_
                    }
                }
            }

            if ($outputFileName -match "\.json$") {
                if($resultItems){
                    ConvertTo-OrderedDictionary $resultItems | ConvertTo-Json -depth 100 | Out-File (New-Item -Path $outputFileName -Force)
                }
            } else {
                foreach($resultItem in $resultItems) {
                    if (!$resultItem.ContainsKey('id')) {
                        continue
                    }
                    $itemOutputFileName = Join-Path -Path $outputFileName -ChildPath $resultItem.id
                    $parentOutputFileName = Join-Path $itemOutputFileName -ChildPath $resultItem.id
                    ConvertTo-OrderedDictionary $resultItem | ConvertTo-Json -depth 100 | Out-File (New-Item -Path "$($parentOutputFileName).json" -Force)
                    if ($item.ContainsKey('Children')) {
                        $itemParents = $Parents
                        $itemParents += $resultItem.Id
                        Export-AzureAD -Path $itemOutputFileName -Type $Type -ExportSchema $item.Children -Parents $itemParents
                    }
                }
            }
        }
    }
}