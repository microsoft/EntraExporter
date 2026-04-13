function Invoke-FilePathCheck {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $FilePath
    )

    if ($env:OS -eq "Windows_NT" -and $FilePath.Length -gt 255 -and (Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -ErrorAction SilentlyContinue) -ne 1){
        Write-Warning "Output file path '$FilePath' is longer than 255 characters. Enable long path support to enable export!"
        return $false
    } else {
        return $true
    }
}