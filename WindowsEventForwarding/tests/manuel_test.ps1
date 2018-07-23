# Prereqs
Set-PSFConfig psframework.message.info.maximum 9
Set-PSFConfig psframework.message.info.maximum 3
set-PSFConfig WindowsEventForwarding.Import.DoDotSource 1
Set-Location C:\Administration\WindowsPowerShell\Development\WindowsEventForwarding\WindowsEventForwarding
Import-Module .\WindowsEventForwarding.psd1 -Force
Remove-Module WindowsEventForwarding -Force

# WEF Settings
$Name = "test"
$Name = "Collector_MachineAccountBased_Test01"

$LogFile = "ForwardedEvents"
$LogFile = "ForwardedEvents_NotExisting"

$Query = '<Select Path="Security">*[System[(Level=1 )]]</Select>'
$Query = '<Select Path="Security">*[System[(Level=1 )]]</Select>', '<Select Path="Security">*[System[(Level=1 )]]</Select>'

$SourceComputer = "Domain computers"
$SourceComputer = "Domain computers not existing"

$Enabled = $true
$Enabled = $false

# target workspace
# remote
$PSDefaultParameterValues = @{
    "Get-WEFSubscription:ComputerName"="srv-tst-log01"
    "New-WEF*:ComputerName"="srv-tst-log01"
}
# local
$PSDefaultParameterValues = @{}


Get-WEFSubscription | Format-Table -AutoSize
Get-WEFSubscription | Get-WEFSubscriptionRuntimestatus | Format-Table
New-WEFSubscription -Name $Name -Type CollectorInitiated -LogFile $LogFile -Query $Query -SourceComputer $SourceComputer -ReadExistingEvents $false -Enabled $Enabled -Description (Get-Date -Format s).ToString() -ContentFormat Events -Locale en-US
New-WEFSubscription -Name $Name -Type SourceInitiated    -LogFile $LogFile -Query $Query -SourceComputer $SourceComputer -ReadExistingEvents $false -Enabled $Enabled -Description (Get-Date -Format s).ToString() -ContentFormat Events -Locale en-US
Get-WEFSubscription -Name $Name | Format-List
Get-WEFSubscription -Name $Name | Get-WEFSubscriptionRuntimestatus | Format-Table
Get-WEFSubscription -Name $Name | Set-WEFSubscription -Description (Get-Date -Format s) -Enabled (-not $Enabled) -Verbose


Get-WEFSubscription | Out-GridView -OutputMode Multiple | Set-WEFSubscription -Status $false
Get-WEFSubscription | Out-GridView -OutputMode Multiple | Set-WEFSubscription -Status $true


Get-WEFSubscription -Name $Name | Resume-WEFSubscription -PassThru
Get-WEFSubscription -Name $Name | Remove-WEFSubscription -Force



# Proxy commands
$MetaData = New-Object System.Management.Automation.CommandMetaData (Get-Command  Set-WEFSubscription)
[System.Management.Automation.ProxyCommand]::Create($MetaData) | Set-Clipboard