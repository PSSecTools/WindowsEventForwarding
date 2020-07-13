<#
    .SYNOPSIS
        This script publishes the module to the gallery.

    .DESCRIPTION
        This script publishes the module to the gallery.
        It expects as input an ApiKey authorized to publish the module.

        Insert any build steps you may need to take before publishing it here.

    .PARAMETER ModuleName
        The name to give to the module.

    .PARAMETER ApiKey
        The API key to use to publish the module to a Nuget repository

    .PARAMETER WorkingDirectory
        The root folder from which to build the module.

    .PARAMETER Repository
        The name of the repository to publish to.
        Defaults to PSGallery.

    .PARAMETER LocalRepo
        Instead of publishing to a gallery, drop a nuget package in the root folder.
        This package can then be picked up in a later step for publishing to Azure Artifacts.

    .PARAMETER SkipPublish
        Skips the publishing to the Nuget repository

    .PARAMETER AutoVersion
        Tells the publishing script to look for the versioning itself. Means,
        if the version in the module needs to be raised, the versioning mechanism
        will reaise the build number by +1
#>
param (
    $ModuleName,

    $ApiKey,

    $WorkingDirectory,

    $Repository = 'PSGallery',

    [switch]
    $LocalRepo,

    [switch]
    $SkipPublish,

    [switch]
    $AutoVersion
)

#region prerequisites
# Handle Working Directory Defaults
if (-not $WorkingDirectory) {
    if ($env:RELEASE_PRIMARYARTIFACTSOURCEALIAS) {
        $WorkingDirectory = Join-Path -Path $env:SYSTEM_DEFAULTWORKINGDIRECTORY -ChildPath $env:RELEASE_PRIMARYARTIFACTSOURCEALIAS
    } else { $WorkingDirectory = $env:SYSTEM_DEFAULTWORKINGDIRECTORY }
}
if (-not $WorkingDirectory) { $WorkingDirectory = Split-Path $PSScriptRoot }

# Check module path
if(-not (Test-Path -Path "$($WorkingDirectory)\$($ModuleName)")) {
    Stop-PSFFunction -Message "Unable to find module $($ModuleName). Maybe wrong module name specified" -EnableException $true
}

# Prepare publish folder
Write-PSFMessage -Level Important -Message "Creating and populating publishing directory"
$publishDir = New-Item -Path $WorkingDirectory -Name "publish" -ItemType Directory -Force
Copy-Item -Path "$($WorkingDirectory)\$($ModuleName)" -Destination $publishDir.FullName -Recurse -Force
#endregion prerequisites

#region Gather text data to compile
$text = @()
$processed = @()

# Gather Stuff to run before
foreach ($filePath in (& "$($PSScriptRoot)\..\$($ModuleName)\internal\scripts\preimport.ps1")) {
    if ([string]::IsNullOrWhiteSpace($filePath)) { continue }

    $item = Get-Item $filePath
    if ($item.PSIsContainer) { continue }
    if ($item.FullName -in $processed) { continue }
    $text += [System.IO.File]::ReadAllText($item.FullName)
    $processed += $item.FullName
}

# Gather commands
Get-ChildItem -Path "$($publishDir.FullName)\$($ModuleName)\internal\functions\" -Recurse -File -Filter "*.ps1" | ForEach-Object {
    $text += [System.IO.File]::ReadAllText($_.FullName)
}
Get-ChildItem -Path "$($publishDir.FullName)\$($ModuleName)\functions\" -Recurse -File -Filter "*.ps1" | ForEach-Object {
    $text += [System.IO.File]::ReadAllText($_.FullName)
}

# Gather stuff to run afterwards
foreach ($filePath in (& "$($PSScriptRoot)\..\$($ModuleName)\internal\scripts\postimport.ps1")) {
    if ([string]::IsNullOrWhiteSpace($filePath)) { continue }

    $item = Get-Item $filePath
    if ($item.PSIsContainer) { continue }
    if ($item.FullName -in $processed) { continue }
    $text += [System.IO.File]::ReadAllText($item.FullName)
    $processed += $item.FullName
}
#endregion Gather text data to compile

#region Update the psm1 file
$fileData = Get-Content -Path "$($publishDir.FullName)\$($ModuleName)\$($ModuleName).psm1" -Raw
$fileData = $fileData.Replace('"<was not compiled>"', '"<was compiled>"')
$fileData = $fileData.Replace('"<compile code into here>"', ($text -join "`n`n"))
[System.IO.File]::WriteAllText("$($publishDir.FullName)\$($ModuleName)\$($ModuleName).psm1", $fileData, [System.Text.Encoding]::UTF8)
#endregion Update the psm1 file

#region Updating the Module Version
if ($AutoVersion) {
    Write-PSFMessage -Level Important -Message "Updating module version numbers."

    $remoteModule = Find-Module '$($ModuleName)' -Repository $Repository -ErrorAction SilentlyContinue
    [version]$remoteVersion = $remoteModule.Version
    if(-not $remoteVersion) { [version]$remoteVersion = [version]::new(0, 0, 0, 0) }

    [version]$localVersion = (Import-PowerShellDataFile -Path "$($publishDir.FullName)\$($ModuleName)\$($ModuleName).psd1").ModuleVersion

    if($remoteVersion -eq $localVersion) {
        [version]$newVersion = [version]::new($localVersion.Major, $localVersion.Minor, $remoteVersion.Build + 1, 0)
    } elseif($remoteVersion -gt $localVersion) {
        [version]$newVersion = [version]::new($remoteVersion.Major, $remoteVersion.Minor, $remoteVersion.Build + 1, 0)
    } else {
        [version]$newVersion = $localVersion
    }

    Update-ModuleManifest -Path "$($publishDir.FullName)\$($ModuleName)\$($ModuleName).psd1" -ModuleVersion "$($newVersion)"
}
#endregion Updating the Module Version

#region Publish
if ($SkipPublish) { return }
if ($LocalRepo) {
    # Dependencies must go first
    Write-PSFMessage -Level Important -Message "Creating Nuget Package for module: PSFramework"
    New-PSMDModuleNugetPackage -ModulePath (Get-Module -Name PSFramework).ModuleBase -PackagePath .
    Write-PSFMessage -Level Important -Message "Creating Nuget Package for module: $($ModuleName)"
    New-PSMDModuleNugetPackage -ModulePath "$($publishDir.FullName)\$($ModuleName)" -PackagePath .
} else {
    # Publish to Gallery
    Write-PSFMessage -Level Important -Message "Publishing the $($ModuleName) module to $($Repository)"
    Publish-Module -Path "$($publishDir.FullName)\$($ModuleName)" -NuGetApiKey $ApiKey -Force -Repository $Repository
}
#endregion Publish