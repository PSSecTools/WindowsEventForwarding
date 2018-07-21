function New-WEFCollectorInitiatedSubscription {
    <#
        .Synopsis
            New-WEFCollectorInitiatedSubscription

        .DESCRIPTION
            Create a new Windows Eventlog Forwarding subscription(s) from type CollectorInitiated.

        .PARAMETER ComputerName
            The computer(s) to connect to.
            Supports PSSession objects, will reuse sessions.

            Aliases for the parameter: "host", "hostname", "Computer", "DNSHostName"

        .PARAMETER Session
            The PSSession object(s) to connect to.

        .PARAMETER Credential
            A credential object used for the connection to remote computer(s) or session(s).

        .PARAMETER Name
            Name of the subscription to filter by.

            Aliases for the parameter: "DisplayName", "SubscriptionID", "Idendity"

        .PARAMETER Description
            The description of the Windows Event Forwarding subscription.

        .PARAMETER Enabled
            Status of the subscription after it is created.

            Aliases for the parameter: "Enable", "Status"

        .PARAMETER ReadExistingEvents
            Specifies that the subscription gathers only new events when it applies on a source.
            True  = All existing events on the source computer will be gathered when the subscription apply.
            False = Only newly created events are gathered after the subscription applies.

        .PARAMETER ContentFormat
            The format for the data transfered to the server.
            Events       = Binary event data are transfered from the source computer to the destition WEF server. Localization apply on the WEF server
            RenderedText = Localized data from the source computer are transfered to the WEF server. (This format contains more bandwidth)

        .PARAMETER LogFile
            The name of the Windows Event Log where the collected events are stored on the WEF server.

        .PARAMETER Locale
            The localization format for the collected events.
            This setting only apply, when ContentFormat is set to "RenderedText"

        .PARAMETER Query
            The filter query for the events to collect. One or more queries must be specified.

            Example: <Select Path="System">*[System[(Level=1  or Level=2 or Level=3)]]</Select>

        .PARAMETER ConfigurationMode
            The timing setting for the event delivery on a subscription.
            There are 4 different settings available - "Normal", "MinBandwidth", "MinLatency", "Custom".
            "Normal"       = MaxLatency and HeartBeatInterval is "00:15:00"
            "MinBandwidth" = MaxLatency and HeartBeatInterval is "06:00:00"
            "MinLatency"   = MaxLatency is "00:00:30" and HeartBeatInterval is "01:00:00"
            "Custom"       = Parameters MaxLatency and HeartBeatInterval has to be specified individually.

            Default is "Normal"

        .PARAMETER MaxLatency
            The timespan for the max. latency when transmitting events.
            MaxLatency is relevent when parmeter ConfigurationMode is set to "Custom". Otherwise the MaxLatency
            will be ignored.

            Default is "00:15:00"

        .PARAMETER HeartBeatInterval
            The timespan for the keep alive signal from the source computer to the WEF server
            MaxLatency is relevent when parmeter ConfigurationMode is set to "Custom". Otherwise the HeartBeatInterval
            will be ignored.

            Default is "00:15:00"

        .PARAMETER MaxItems
            The maximum amount of events on a delivery process.
            This is a optional setting and not configured by default.

        .PARAMETER TransportName
            Specifies that the transport layer for the forwarded events. Can be set to "http" (default)
            or "https", which add an additional layer of transport security. (PKI/certificates needed on the
            machines).
            In a domain environment transmit is encrypted via kerberos. The authentication is done via kerberos
            (domain) or with ntlm (workgroup). Authentication is encrypted regardless to the transport security.
            Transport security is only needed outside a domain environment for the event transmit.

            Default is http.

        .PARAMETER SourceComputer
            The name(s) or SID(s) for the group(s) or computer(s) the subscription should apply.

        .PARAMETER Expires
            The date when the created subscription will expire.

        .EXAMPLE
            PS C:\> New-WEFCollectorInitiatedSubscription -Name "MySubscription" -LogFile "ForwardedEvents" -Query '<Select Path="Security">*[System[(Level=1 )]]</Select>' -SourceDomainComputer "Server1"

            Create a new CollectorInitiated subscription "MySubScription"

        .NOTES
            Author: Andreas Bellstedt

        .LINK
            https://github.com/AndiBellstedt/WindowsEventForwarding
    #>
    [CmdletBinding(DefaultParameterSetName ='ComputerName',
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium',
        RemotingCapability = 'SupportedByCommand')]
    Param(
        [Parameter(ParameterSetName='ComputerName', Position=1, ValueFromPipeline=$true)]
        [Alias('host','hostname','Computer','DNSHostName')]
        [PSFramework.Parameter.ComputerParameter[]]
        ${ComputerName},

        [Parameter(ParameterSetName='Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        ${Session},

        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Alias('DisplayName','SubscriptionID','Idendity')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Name,

        [ValidateNotNullOrEmpty()]
        [string]
        ${Description},

        [Alias('Enable','Status')]
        [bool]
        ${Enabled},

        [bool]
        ${ReadExistingEvents},

        [ValidateSet('Events','RenderedText')]
        [string]
        ${ContentFormat},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${LogFile},

        [ValidateSet('en-US','de-DE','fr-FR','es-ES','nl-NL','it-IT','af-ZA','cs-CZ','en-GB','en-NZ','en-TT','es-PR','ko-KR','sk-SK','zh-CN','zh-HK')]
        [string]
        ${Locale},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Query},

        [ValidateNotNullOrEmpty()]
        [ValidateSet('Normal','MinBandwidth','MinLatency','Custom')]
        [string]
        ${ConfigurationMode},

        [ValidateNotNullOrEmpty()]
        [timespan]
        ${MaxLatency},

        [ValidateNotNullOrEmpty()]
        [timespan]
        ${HeartBeatInterval},

        [ValidateNotNullOrEmpty()]
        [int]
        ${MaxItems},

        [ValidateSet('HTTP','HTTPS')]
        [string]
        ${TransportName},

        [ValidateNotNull()]
        [string[]]
        ${SourceComputer},

        [ValidateNotNullOrEmpty()]
        [datetime]
        ${Expires})

    begin
    {
        try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('New-WEFSubscription', [System.Management.Automation.CommandTypes]::Function)
            $scriptCmd = {& $wrappedCmd -Type "CollectorInitiated" @PSBoundParameters }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline()
            $steppablePipeline.Begin($PSCmdlet)
        } catch {
            throw
        }
    }

    process
    {
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
    }

    end
    {
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
    }
}