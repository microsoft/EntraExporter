# Build script for EntraExporter PowerShell Module

param(
    [ValidateSet('Build', 'Test', 'Publish', 'Install', 'Clean')]
    [string]$Task = 'Build',

    [string]$OutputPath = './release/EntraExporter',

    [string]$Repository = 'PSGallery',

    [string]$ApiKey
)

# Clean output directory
function Invoke-Clean {
    if (Test-Path $OutputPath) {
        Remove-Item -Path $OutputPath -Recurse -Force
        Write-Host "Cleaned output directory: $OutputPath" -ForegroundColor Green
    }
}

# Build the module
function Invoke-Build {
    Write-Host "Building module..." -ForegroundColor Cyan

    # Clean first
    Invoke-Clean

    # Copy module files including subfolders
    Write-Host "Copying module files to $OutputPath..." -ForegroundColor Yellow
    Copy-Item -Path './src' -Destination $OutputPath -Recurse

    Write-Host "Module built successfully in: $OutputPath" -ForegroundColor Green
}

# Test the module
function Invoke-Test {
    Write-Host "Testing module..." -ForegroundColor Cyan

    # Import the module
    Import-Module "$OutputPath/EntraExporter.psd1" -Force

    # Test module manifest
    $manifest = Test-ModuleManifest "$OutputPath/EntraExporter.psd1"
    if ($manifest) {
        Write-Host "✅ Module manifest is valid" -ForegroundColor Green
        Write-Host "   Version: $($manifest.Version)" -ForegroundColor White
        Write-Host "   Author: $($manifest.Author)" -ForegroundColor White
        Write-Host "   Description: $($manifest.Description)" -ForegroundColor White
    } else {
        Write-Error "❌ Module manifest validation failed"
        return $false
    }

    Write-Host "✅ All tests passed!" -ForegroundColor Green
    return $true
}

# Install the module locally
function Invoke-Install {
    Write-Host "Installing EntraExporter module locally..." -ForegroundColor Cyan

    # Get user module path
    $userModulePath = $env:PSModulePath.Split([IO.Path]::PathSeparator) |
        Where-Object { $_ -like "*$env:USERNAME*" -or $_ -like "*Users*" } |
        Select-Object -First 1

    if (-not $userModulePath) {
        $userModulePath = "$env:USERPROFILE\Documents\PowerShell\Modules"
    }

    $installPath = Join-Path $userModulePath "EntraExporter"

    # Remove existing installation
    if (Test-Path $installPath) {
        Remove-Item -Path $installPath -Recurse -Force
        Write-Host "Removed existing installation" -ForegroundColor Yellow
    }

    # Create directory and copy files
    New-Item -Path $installPath -ItemType Directory -Force | Out-Null
    Copy-Item -Path "$OutputPath/*" -Destination $installPath -Recurse

    Write-Host "Module installed to: $installPath" -ForegroundColor Green
    Write-Host "You can now use: Import-Module EntraExporter" -ForegroundColor Cyan
}

# Publish the module
function Invoke-Publish {
    if (-not $ApiKey) {
        Write-Error "API Key is required for publishing. Use -ApiKey parameter."
        return
    }

    Write-Host "Publishing EntraExporter module to $Repository..." -ForegroundColor Cyan

    try {
        Publish-Module -Path $OutputPath -Repository $Repository -NuGetApiKey $ApiKey
        Write-Host "✅ Module published successfully!" -ForegroundColor Green
    }
    catch {
        Write-Error "❌ Failed to publish module: $($_.Exception.Message)"
    }
}

# Main execution
switch ($Task) {
    'Build' { Invoke-Build }
    'Test' {
        Invoke-Build
        Invoke-Test
    }
    'Publish' {
        Invoke-Build
        if (Invoke-Test) {
            Invoke-Publish
        }
    }
    'Install' {
        Invoke-Build
        if (Invoke-Test) {
            Invoke-Install
        }
    }
    'Clean' { Invoke-Clean }
}
