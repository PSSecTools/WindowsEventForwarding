function Rename-WEFSubscription {
    <#
        .Synopsis
            Rename-WEFSubscription

        .DESCRIPTION
            Change the name of Windows Eventlog Forwarding subscription(s)

        .PARAMETER InputObject
            Pipeline catching object for Get-WEFSubscription

        .PARAMETER ComputerName
            The computer(s) to connect to.
            Supports PSSession objects, will reuse sessions.

            Available aliases: "host", "hostname", "Computer", "DNSHostName"

        .PARAMETER Session
            PSSession(s) to connect to.

        .PARAMETER Name
            Name of the subscription to modify.
            Only needed when InputObject is not used.
            Must be specified when piping in a computername or PSSession.

            Available aliases: "DisplayName", "SubscriptionID", "Idendity"

        .PARAMETER NewName
            The new name for the subscription.

        .PARAMETER Credential
            The credentials to use on remote calls.

        .PARAMETER PassThru
            Output the changed subscription on the end of the operation

        .EXAMPLE
            PS C:\> Rename-WEFSubscription -Name "Subscription1" -NewName "Subscription001"

            Change the name of subscription "Subscription1" to "Subscription001"

        .EXAMPLE
            PS C:\> Get-WEFSubscription -Name "Subscription1" | Rename-WEFSubscription -NewName "Subscription001"

            Change the name of "Subscription1" to "Subscription001" by using the pipeline.

        .NOTES
            Author: Andreas Bellstedt

        .LINK
            https://github.com/AndiBellstedt/WindowsEventForwarding
    #>
    [CmdletBinding(DefaultParameterSetName = 'ComputerName',
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium')]
    param(
        [Parameter(ParameterSetName = 'InputObject', Position = 0, ValueFromPipeline = $true)]
        [WEF.Subscription[]]
        ${InputObject},

        [Parameter(ParameterSetName = 'Session', Position = 0)]
        [Parameter(ParameterSetName = 'ComputerName', Position = 0)]
        [Alias('DisplayName', 'SubscriptionID', 'Idendity')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Name},

        [Parameter(ParameterSetName = 'ComputerName', Position = 2, ValueFromPipeline = $true)]
        [Alias('host', 'hostname', 'Computer', 'DNSHostName')]
        [PSFramework.Parameter.ComputerParameter[]]
        ${ComputerName},

        [Parameter(ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        ${Session},

        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $NewName,

        [switch]
        ${PassThru}
    )
    begin {
        try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Set-WEFSubscription', [System.Management.Automation.CommandTypes]::Function)
            $scriptCmd = {& $wrappedCmd @PSBoundParameters }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline()
            $steppablePipeline.Begin($PSCmdlet)
        } catch {
            throw
        }
    }

    process {
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
    }

    end {
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
    }
}