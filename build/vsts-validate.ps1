<#
    .SYNOPSIS
        This script ensure things are done right

    .DESCRIPTION
        Needs to ensure things are Done Right and only legal commits or pull requests get into the branch

    .NOTES
        Guide for available variables and working with secrets:
        https://docs.microsoft.com/en-us/vsts/build-release/concepts/definitions/build/variables?tabs=powershell

    .PARAMETER ModuleName
        The name to give to the module.
#>
param (
    $ModuleName
)

# Run internal pester tests
& "$PSScriptRoot\..\$($ModuleName)\tests\pester.ps1"