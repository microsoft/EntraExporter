function Invoke-RoleEligibilityScheduleRequestIdSimplification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $id
    )

    $joinChar = [System.IO.Path]::DirectorySeparatorChar

    # simplify the id to create more readable file names and avoid too long path issues
    $id = $id -replace "/subscriptions/", ""
    $id = $id -replace "/providers/Microsoft.Management/managementGroups/", ""
    
    $id = $id -replace "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests", ""
    # replace remaining "/" with directory separator char to create folder structure based on scope and assignment id
    $id = $id -replace "/", $joinChar

    $id
}