Windows Event Forwarding
====================

A module for working with Windows Event Collector service and maintain Windows Event Forwarding subscriptions.

# Purpose

Welcome to the PowerShell Windows Event Forwarding (WEF) module. A module designed to make the administration of a WEF Server comfortable. This fits especially on machines with more than a bunch of subscriptions.

All cmdlets are built with
- PowerShell regular verbs
- Prefix WEF in any noun
- Mostly with pipeline availabilities
- Comprehensive logging


Effectively, the module is a wrapper around the command line utility ```wecutil.exe``` of the windows event forwarding platform, but with a lot more convenience and remoting capabilities.

#
## Installation
The module isn't in the PowerShellGallery, yet.

In order to get started with the latest production build, simply run this in an elevated console:
 ```powershell
 Invoke-WebRequest "https://raw.githubusercontent.com/AndiBellstedt/WindowsEventForwarding/master/install.ps1" -UseBasicParsing | Invoke-Expression
 ```
 This will install the module on your system, ready for use

## Example
Every function has examples:
```powershell
    Get-Help Get-WEFSubscription -Examples

    Get-Help New-WEFSubscription -Examples
```
This will query subscriptions from the local system:
```powershell
    Get-WEFSubscription -Name MySubscription, Subscription2
```
The functions will also work on a remote system:
```powershell
    Get-WEFSubscription -Name MySubscription -ComputerName Server01

    "MySubscription" | Get-WEFSubscription -ComputerName Server01

    "Server01" | Get-WEFSubscription -Name "MySubscription"
```
For remote administration PSRemoting is used, so be sure to have it properly set up.

## Configuration Notice

This module uses the PSFramework, primarily for logging purpose and for executing remote commands effectively.\
In the future, the configuration management will also be done with PSFramework, maybe.


# Changelog

Changes will be tracked in the [changelog.md](changelog.md)
