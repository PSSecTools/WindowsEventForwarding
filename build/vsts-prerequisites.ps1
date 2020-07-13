<#
    .SYNOPSIS
        This script ensures prerequisites to run tests

    .DESCRIPTION
        This script ensures prerequisites to run tests

    .PARAMETER ModuleName
        The name to give to the module.

    .PARAMETER Repository
        The name of the repository to publish to.
        Defaults to PSGallery.

#>
param (
    [string]
    $ModuleName,

    [string]
    $Repository = 'PSGallery',

    $Modules = @("Pester", "PSModuleDevelopment", "PSScriptAnalyzer")
)


# Automatically add missing dependencies
$data = Import-PowerShellDataFile -Path "$PSScriptRoot\..\$($ModuleName)\$($ModuleName).psd1"
foreach ($dependency in $data.RequiredModules) {
    if ($dependency -is [string]) {
        if ($Modules -contains $dependency) { continue }
        $Modules += $dependency
    }
    else {
        if ($Modules -contains $dependency.ModuleName) { continue }
        $Modules += $dependency.ModuleName
    }
}

foreach ($module in $Modules) {
    Write-Host "Installing $module" -ForegroundColor Cyan
    Install-Module $module -Force -SkipPublisherCheck -Repository $Repository
    Import-Module $module -Force -PassThru
}