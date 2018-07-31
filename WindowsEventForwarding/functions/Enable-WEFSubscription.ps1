function Enable-WEFSubscription {
    <#
        .Synopsis
            Enable-WEFSubscription

        .DESCRIPTION
            Enable Windows Eventlog Forwarding subscription(s)

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

        .PARAMETER Credential
            The credentials to use on remote calls.

        .PARAMETER WhatIf

            If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

        .PARAMETER Confirm

            If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

        .PARAMETER PassThru

            If this switch is enabled, the function will return the working object to the pipeline for further processing

        .EXAMPLE
            PS C:\> Enable-WEFSubscription -Name "Subscription1"

            Enable the subscription "Subscription1"

        .EXAMPLE
            PS C:\> Get-WEFSubscription -Name "Subscription1" | Enable-WEFSubscription

            Enable "Subscription1" by using the pipeline.

        .NOTES
            Author: Andreas Bellstedt

        .LINK
            https://github.com/AndiBellstedt/WindowsEventForwarding
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSShouldProcess", "")]
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

        [Parameter(ParameterSetName = 'ComputerName', Position = 1, ValueFromPipeline = $true)]
        [Alias('host', 'hostname', 'Computer', 'DNSHostName')]
        [PSFramework.Parameter.ComputerParameter[]]
        ${ComputerName},

        [Parameter(ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        ${Session},

        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},

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
            $scriptCmd = {& $wrappedCmd -Enabled $true @PSBoundParameters }
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