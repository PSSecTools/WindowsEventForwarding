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




<#
######################################################################
wecutil.exe gr ASL_GPO | Set-Clipboard  #SRV-TST-LOG01

Subscription: ASL_GPO
	RunTimeStatus: Active
	LastError: 0
	EventSources:
		SRV-TST-DC01.test.andibell.de
			RunTimeStatus: Active
			LastError: 0
			LastHeartbeatTime: 2018-07-24T21:58:07.503
		SRV-TST-RRAS01.test.andibell.de
			RunTimeStatus: Inactive
			LastError: 0
			LastHeartbeatTime: 2018-05-31T17:54:51.321


wecutil.exe gr Collector | Set-Clipboard  #XPS-AB

Subscription: Collector
	RunTimeStatus: Active
	LastError: 0
	EventSources:
		XPS-AB
			RunTimeStatus: Trying
			LastError: 5
			ErrorMessage: <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="5" Machine="XPS-AB"><f:Message>Zugriff verweigert </f:Message></f:WSManFault>
			ErrorTime: 2018-07-24T21:57:28.295
			NextRetryTime: 2018-07-24T22:57:28.295

SubscriptionId            : collector
SubscriptionRuntimeStatus : Active
SubscriptionLastError     : 0
SourceId                  : XPS-AB
SourceRunTimeStatus       : Trying
SourceLastError           : 5
SourceErrorMessage        : <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="5" Machine="XPS-AB"><f:Message>Zugriff verweigert</f:Message></f:WSManFault>
SourceErrorTime           : 2018-07-24T19:57:28.255
SourceNextRetryTime       : 2018-07-24T20:57:28.255


wecutil.exe gr NonDomain | Set-Clipboard  #SRV-TST-LOG01
Subscription: NonDomain
	RunTimeStatus: Active
	LastError: 0



######################################################################
wecutil.exe gr test | Set-Clipboard  #XPS-AB

Subscription: test
	RunTimeStatus: Inactive
	LastError: -2144108183
	ErrorMessage: <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150859113" Machine="XPS-AB"><f:Message>Die WinRM-Firewallausnahme funktioniert nicht, da einer der Netzwerkverbindungstypen auf diesem Computer auf &quot;Öffentlich&quot; festgelegt ist. Ändern Sie den Netzwerkverbindungstyp entweder in &quot;Domäne&quot; oder in &quot;Privat&quot;, und wiederholen Sie den Vorgang. </f:Message></f:WSManFault>
	ErrorTime: 2018-07-24T07:11:14.617



######################################################################
wecutil.exe gr source | Set-Clipboard  #XPS-AB

Subscription: source
	RunTimeStatus: Disabled
	LastError: 0




#>
