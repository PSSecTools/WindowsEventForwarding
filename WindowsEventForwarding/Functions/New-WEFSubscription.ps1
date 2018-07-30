function New-WEFSubscription {
    <#
        .Synopsis
            New-WEFSubscription

        .DESCRIPTION
            Create a new Windows Eventlog Forwarding subscription(s).

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

        .PARAMETER Type
            The type of the subscription.

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

        .PARAMETER SourceDomainComputer
            The name(s) or SID(s) for the group(s) or computer(s) the subscription should apply.
            This Parameter apply the both subscription type, "SourceInitiated" and "CollectorInitiated".

            Aliases for the parameter: "SourceComputer"

        .PARAMETER SourceNonDomainDNSList
            DNS name patterns for WEF clients that should aplly to the subscription.
            This Parameter apply only to a "SourceInitiated" subscription.

        .PARAMETER SourceNonDomainIssuerCAThumbprint
            Certificate thumbprint(s) of trusted certifcates of a WEF collector/server.
            This Parameter apply only to a "SourceInitiated" subscription.

        .PARAMETER Expires
            The date when the created subscription will expire.

        .EXAMPLE
            PS C:\> New-WEFSubscription -Name "MySubscription" -Type CollectorInitiated -LogFile "ForwardedEvents" -Query '<Select Path="Security">*[System[(Level=1 )]]</Select>' -SourceDomainComputer "Server1"

            Create a new CollectorInitiated subscription "MySubScription"

        .EXAMPLE
            PS C:\> New-WEFSubscription -Name "MySubscription" -Type SourceInitiated -LogFile "ForwardedEvents" -Query '<Select Path="Security">*[System[(Level=1 )]]</Select>' -SourceDomainComputer "Domain computers"

            Create a new SourceInitiated subscription "MySubScription"

        .NOTES
            Author: Andreas Bellstedt

        .LINK
            https://github.com/AndiBellstedt/WindowsEventForwarding
    #>
    [CmdletBinding(DefaultParameterSetName = 'ComputerName',
        SupportsShouldProcess = $true,
        ConfirmImpact = 'medium')]
    Param(
        [Parameter(ParameterSetName = "ComputerName", ValueFromPipeline = $true, Position = 1)]
        [Alias("host", "hostname", "Computer", "DNSHostName")]
        [PSFComputer[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = "Session")]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [PSCredential]
        $Credential,

        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [Alias("DisplayName", "SubscriptionID", "Idendity")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet("SourceInitiated", "CollectorInitiated")]
        [string]
        $Type,

        [ValidateNotNullOrEmpty()]
        [string]
        $Description = "",

        [Alias("Enable", "Status")]
        [bool]
        $Enabled = $true,

        [bool]
        $ReadExistingEvents = $false,

        [ValidateSet("Events", "RenderedText")]
        [string]
        $ContentFormat = "RenderedText",

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $LogFile,

        [ValidateSet("en-US", "de-DE", "fr-FR", "es-ES", "nl-NL", "it-IT", "af-ZA", "cs-CZ", "en-GB", "en-NZ", "en-TT", "es-PR", "ko-KR", "sk-SK", "zh-CN", "zh-HK")]
        [string]
        $Locale = (Get-WinSystemLocale).Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Query,

        [ValidateSet("Normal", "MinBandwidth", "MinLatency", "Custom")]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfigurationMode = "Normal",

        [ValidateNotNullOrEmpty()]
        [timespan]
        $MaxLatency = "00:15:00",

        [ValidateNotNullOrEmpty()]
        [timespan]
        $HeartBeatInterval = "00:15:00",

        [ValidateNotNullOrEmpty()]
        [int]
        $MaxItems,

        [ValidateSet("HTTP", "HTTPS")]
        [string]
        $TransportName = "HTTP",

        [ValidateNotNull()]
        [Alias("SourceComputer")]
        [String[]]
        $SourceDomainComputer,

        [ValidateNotNull()]
        [string[]]
        $SourceNonDomainDNSList,

        [ValidateNotNull()]
        [string[]]
        $SourceNonDomainIssuerCAThumbprint,

        [ValidateNotNullOrEmpty()]
        [datetime]
        $Expires
    )

    Begin {
        # If session parameter is used -> transfer it to ComputerName,
        # The class "PSFComputer" from PSFramework can handle it. This simplifies the handling in the further process block
        if ($Session) { $ComputerName = $Session }

        $nameBound = Test-PSFParameterBinding -ParameterName Name
        $computerBound = Test-PSFParameterBinding -ParameterName ComputerName

        # Check prerequisites on parameters
        if(-not (Test-PSFParameterBinding -ParameterName SourceDomainComputer, SourceNonDomainDNSList, SourceNonDomainIssuerCAThumbprint)) {
            Stop-PSFFunction -Message "No source list specified for the subscription. At least one of the parameter 'SourceDomainComputer, SourceNonDomainDNSList, SourceNonDomainIssuerCAThumbprint' has to be specified." -EnableException $true
        }

        if( $Type -eq "CollectorInitiated") {
            # Parameter SourceNonDomainDNSList, SourceNonDomainIssuerCAThumbprint are only supportet on SourceInitated subscriptions
            if(Test-PSFParameterBinding -ParameterName SourceNonDomainDNSList, SourceNonDomainIssuerCAThumbprint) {
                Write-PSFMessage -Level Warning -Message "Incompatible sources for CollectorInitiated subscription. The type of the subscription is set to 'CollectorInitiated' and parameter 'SourceNonDomainDNSList' or 'SourceNonDomainIssuerCAThumbprint' is specified. This is not possible and the values will be ignored. Only parameter 'SourceDomainComputer' can be specified as a source on CollectorInitiated subscription(s)."
            }
            Remove-Variable -Name SourceNonDomainDNSList, SourceNonDomainIssuerCAThumbprint -Force -Confirm:$false -Verbose:$false -WhatIf:$false
        }
        if( $Type -eq "CollectorInitiated" -and (-not (Test-PSFParameterBinding -ParameterName SourceDomainComputer))) {
            Stop-PSFFunction -Message "Missing parameter 'SourceDomainComputer' for CollectorInitiated subscription(s)." -EnableException $true
        }

        if( ((Test-PSFParameterBinding -ParameterName ConfigurationMode) -and $ConfigurationMode -notlike "Custom") -and (Test-PSFParameterBinding -ParameterName HeartBeatInterval, MaxLatency) ) {
            # default ConfigurationMode specified as parameter and MaxLatency/HeartBeatInterval also specified
            # --> MaxLatency & HeartBeatInterval will be ignored
            $BoundParameterName = [string]::Join(" and ", ((Get-PSCallStack)[0].InvocationInfo.BoundParameters.Keys).where({$_ -in "MaxLatency","HeartBeatInterval"}))
            Write-PSFMessage -Level Important -Message "ConfigurationMode '$($ConfigurationMode)' specified together with $( $BoundParameterName ). The ConfigurationMode will overwrite the values from parameters $($BoundParameterName)."
            switch ($ConfigurationMode) {
                "Normal" {
                    $MaxLatency = [timespan]::new(0,0,0,0,900000)
                    $HeartBeatInterval = [timespan]::new(0,0,0,0,900000)
                }
                "MinBandwidth" {
                    $MaxLatency = [timespan]::new(0,0,0,0,21600000)
                    $HeartBeatInterval = [timespan]::new(0,0,0,0,21600000)
                }
                "MinLatency" {
                    $MaxLatency = [timespan]::new(0,0,0,0,30000)
                    $HeartBeatInterval = [timespan]::new(0,0,0,0,3600000)
                }
                Default {}
            }
        }

        if( $MaxLatency.TotalMilliseconds -eq 900000 -and $HeartBeatInterval.TotalMilliseconds -eq 900000 ) {
            $ConfigurationMode = "Normal"
        } elseif( $MaxLatency.TotalMilliseconds -eq 21600000 -and $HeartBeatInterval.TotalMilliseconds -eq 21600000 ) {
            $ConfigurationMode = "MinBandwidth"
        } elseif( $MaxLatency.TotalMilliseconds -eq 30000 -and $HeartBeatInterval.TotalMilliseconds -eq 3600000 ) {
            $ConfigurationMode = "MinLatency"
        } else {
            $ConfigurationMode = "Custom"
        }

        # Optional parameters - remove variables if not specified
        if(-not (Test-PSFParameterBinding -ParameterName MaxItems)) { Remove-Variable -Name MaxItems -Force -Confirm:$false -Verbose:$false -WhatIf:$false }
        if(-not (Test-PSFParameterBinding -ParameterName Expires)) { Remove-Variable -Name Expires -Force -Confirm:$false -Verbose:$false -WhatIf:$false }
    }

    Process {
        try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { Write-PSFMessage -Level Significant -Message "Exception while setting UTF8 OutputEncoding. Continue script." -ErrorRecord $_ }
        Write-PSFMessage -Level Debug -Message "ParameterNameSet: $($PsCmdlet.ParameterSetName)"
        #region parameterset workarround
        # Workarround parameter binding behaviour of powershell in combination with ComputerName Piping
        if (-not ($nameBound -or $computerBound) -and $ComputerName.InputObject -and $PSCmdlet.ParameterSetName -ne "Session") {
            if ($ComputerName.InputObject -is [string]) { $ComputerName = $env:ComputerName } else { $Name = "" }
        }
        #endregion parameterset workarround

        foreach ($computer in $ComputerName) {
            #region Gathering prerequisites
            Write-PSFMessage -Level VeryVerbose -Message "Processing $computer" -Target $computer

            $paramInvokeCmd = @{
                ComputerName = $computer
                ErrorAction  = "Stop"
            }
            if ($Credential) { $paramInvokeCmd.Add("Credential", $Credential) }

            # Check service 'Windows Event Collector' - without this, there are not subscriptions possible
            Write-PSFMessage -Level Verbose -Message "Checking service 'Windows Event Collector'" -Target $computer
            $service = Invoke-PSFCommand @paramInvokeCmd -ScriptBlock { Get-Service -Name "wecsvc" }
            if ($service.Status -ne 'Running') {
                Stop-PSFFunction -Message "Working with eventlog subscriptions requires  the 'Windows Event Collector' service in running state.  Please ensure that the service is set up correctly or use 'wecutil.exe qc'." -EnableException $true
            }

            if(-not (Invoke-PSFCommand @paramInvokeCmd -ScriptBlock { Get-WinEvent -ListLog $args[0] -ErrorAction SilentlyContinue} -ArgumentList $LogFile)) {
                Stop-PSFFunction -Message "Eventlog '$($LogFile)' not found on computer '$($computer)'. Aborting creation of subscription." -EnableException $true
            }
            #endregion Gathering prerequisites

            #region Processing Events
            foreach ($nameItem in $Name) {
                # Collect all parameters into a hashtable - for easier handling on remoting
                $subscriptionProperties = @{
                    Name                              = $nameItem
                    Type                              = $Type
                    Description                       = $Description
                    Enabled                           = $Enabled
                    ReadExistingEvents                = $ReadExistingEvents
                    ContentFormat                     = $ContentFormat
                    LogFile                           = $LogFile
                    Locale                            = $Locale
                    Query                             = $Query
                    ConfigurationMode                 = $ConfigurationMode
                    Mode                              = if($Type -eq "SourceInitiated") { "Push" } else { "Pull" }
                    MaxLatency                        = $MaxLatency
                    HeartBeatInterval                 = $HeartBeatInterval
                    MaxItems                          = $MaxItems
                    TransportName                     = $TransportName
                    SourceDomainComputer              = $SourceDomainComputer
                    SourceNonDomainDNSList            = $SourceNonDomainDNSList
                    SourceNonDomainIssuerCAThumbprint = $SourceNonDomainIssuerCAThumbprint
                    Expires                           = $Expires
                }

                $invokeParams = @{
                    ComputerName  = $computer
                    ErrorAction   = "Stop"
                    ErrorVariable = "ErrorReturn"
                    ArgumentList  = @(
                        $subscriptionProperties
                        "WEF.$( [system.guid]::newguid().guid ).xml"
                    )
                }
                if ($Credential) { $invokeParams.Add("Credential", $Credential)}

                if ($pscmdlet.ShouldProcess("Subscription: $($nameItem) on computer '$($computer)'", "Create")) {
                    Write-PSFMessage -Level Verbose -Message "Start creating subscription '$($nameItem)' on computer '$($computer)'" -Target $computer
                    $QuerySubscription = $true

                    # Write XML config file in temp folder
                    try {
                        Write-PSFMessage -Level Verbose -Message "Create temporary config file '$($invokeParams.ArgumentList[1])' for new subscription" -Target $computer
                        $null = Invoke-PSFCommand @invokeParams -ScriptBlock {
                            $subscriptionProperties = $args[0]

                            # Create our new XML File
                            $xmlFilePath = $env:TEMP + "\" + $args[1]
                            $XmlWriter = New-Object System.XMl.XmlTextWriter($xmlFilePath, $null)
                            $xmlFilePath = $XmlWriter.BaseStream.Name

                            # Set The Formatting
                            $xmlWriter.Formatting = "Indented"
                            $xmlWriter.Indentation = "4"

                            # Write the XML Decleration
                            $xmlWriter.WriteStartDocument()

                            # Create Subscription
                            $xmlWriter.WriteStartElement("Subscription")
                            $xmlWriter.WriteAttributeString("xmlns", "http://schemas.microsoft.com/2006/03/windows/events/subscription")
                            $xmlWriter.WriteElementString("SubscriptionId", $subscriptionProperties.Name)
                            $xmlWriter.WriteElementString("SubscriptionType", $subscriptionProperties.Type)
                            $xmlWriter.WriteElementString("Description", $subscriptionProperties.Description)
                            $xmlWriter.WriteElementString("Enabled", [bool]::Parse($subscriptionProperties.Enabled))
                            $xmlWriter.WriteElementString("Uri", "http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog")
                            $xmlWriter.WriteElementString("ConfigurationMode", $subscriptionProperties.ConfigurationMode)
                            if($subscriptionProperties.ConfigurationMode -eq "Custom") {
                                $xmlWriter.WriteStartElement("Delivery") # Start Delivery
                                $xmlWriter.WriteAttributeString("Mode", $subscriptionProperties.Mode)
                                $xmlWriter.WriteStartElement("Batching") # Start Batching
                                if($subscriptionProperties.MaxItems) { $xmlWriter.WriteElementString("MaxItems", $subscriptionProperties.MaxItems) }
                                $xmlWriter.WriteElementString("MaxLatencyTime", $subscriptionProperties.MaxLatency.TotalMilliseconds)
                                $xmlWriter.WriteEndElement() # Close Batching
                                $xmlWriter.WriteStartElement("PushSettings") # Start PushSettings
                                $xmlWriter.WriteStartElement("Heartbeat") # Start Heartbeat
                                $xmlWriter.WriteAttributeString("Interval", $subscriptionProperties.HeartBeatInterval.TotalMilliseconds)
                                $xmlWriter.WriteEndElement() # Closing Heartbeat
                                $xmlWriter.WriteEndElement() # Closing PushSettings
                                $xmlWriter.WriteEndElement() # Closing Delivery
                            }
                            if($subscriptionProperties.Expires) { $xmlWriter.WriteElementString("Expires", (Get-Date -Date $subscriptionProperties.Expires -Format s)) }
                            $xmlWriter.WriteStartElement("Query") # Start Query
                            $xmlWriter.WriteCData("<QueryList> <Query Id='0'>`r`t$( [string]::Join("`r`t", ($subscriptionProperties.Query | ForEach-Object { $_ }) ) )`r</Query></QueryList>")
                            $xmlWriter.WriteEndElement() # Closing Query
                            $xmlWriter.WriteElementString("ReadExistingEvents", [bool]::Parse($subscriptionProperties.ReadExistingEvents))
                            $xmlWriter.WriteElementString("TransportName", $subscriptionProperties.TransportName)
                            $xmlWriter.WriteElementString("ContentFormat", $subscriptionProperties.ContentFormat)
                            $xmlWriter.WriteStartElement("locale") # Start Locale
                            $xmlWriter.WriteAttributeString("language", $subscriptionProperties.Locale)
                            $xmlWriter.WriteEndElement() #Closing Locale
                            $xmlWriter.WriteElementString("LogFile", $subscriptionProperties.LogFile)
                            $xmlWriter.WriteElementString("PublisherName", "")

                            if($subscriptionProperties.Type -eq 'SourceInitiated') {
                                # SourceInitiated subscription
                                if($subscriptionProperties.SourceDomainComputer) {
                                    # Parse every value specified, translate from name to SID
                                    $sddlString = "O:NSG:BAD:P"
                                    foreach ($sourceDomainComputerItem in $subscriptionProperties.SourceDomainComputer) {
                                        if($sourceDomainComputerItem -match 'S-1-5-21-(\d|-)*$') {
                                            # sourceDomainComputerItem is a SID, no need to translate
                                            $SID = $sourceDomainComputerItem
                                        } else {
                                            # try to translate name to SID
                                            try {
                                                $SID = [System.Security.Principal.NTAccount]::new( $sourceDomainComputerItem ).Translate([System.Security.Principal.SecurityIdentifier]).Value
                                            } catch {
                                                Write-Error -Message "Cannot convert '$sourceDomainComputerItem' to a valid SID! '$sourceDomainComputerItem' will not be included as SourceDomainComputer in subscription."
                                                return
                                            }
                                        }
                                        # Insert SDDL-String with SID
                                        $sddlString = $sddlString + "(A;;GA;;;" + $SID + ")"
                                        Remove-Variable -Name SID -Force -Confirm:$false -WhatIf:$false -Verbose:$false
                                    }
                                    $sddlString = $sddlString + "S:"

                                    $xmlWriter.WriteElementString("AllowedSourceDomainComputers", $sddlString)
                                    Remove-Variable -Name sddlString -Force -Confirm:$false -WhatIf:$false -Verbose:$false
                                }

                                if($subscriptionProperties.SourceNonDomainDNSList -or $subscriptionProperties.SourceNonDomainIssuerCAThumbprint) {
                                    $xmlWriter.WriteStartElement("AllowedSourceNonDomainComputers") # Start AllowedSourceNonDomainComputers
                                    $xmlWriter.WriteStartElement("AllowedIssuerCAList") # Start AllowedIssuerCAList
                                    foreach ($SourceNonDomainIssuerCAThumbprintItem in $subscriptionProperties.SourceNonDomainIssuerCAThumbprint) {
                                        $xmlWriter.WriteElementString("IssuerCA", $SourceNonDomainIssuerCAThumbprintItem)
                                    }
                                    $xmlWriter.WriteEndElement() # Closing AllowedIssuerCAList
                                    $xmlWriter.WriteStartElement("AllowedSubjectList") # Start AllowedSubjectList
                                    foreach ($SourceNonDomainDNSListItem in $subscriptionProperties.SourceNonDomainDNSList) {
                                        $xmlWriter.WriteElementString("Subject", $SourceNonDomainDNSListItem)
                                    }
                                    $xmlWriter.WriteEndElement() # Closing AllowedSubjectList
                                    $xmlWriter.WriteEndElement() # Closing AllowedSourceNonDomainComputers
                                }
                            } else {
                                # CollectorInitiated subscription
                                $xmlWriter.WriteElementString("CredentialsType", "Default")
                                $xmlWriter.WriteStartElement("EventSources") # Start EventSources
                                foreach ($sourceDomainComputerItem in $subscriptionProperties.SourceDomainComputer) {
                                    $xmlWriter.WriteStartElement("EventSource") # Start EventSource
                                    $xmlWriter.WriteAttributeString("Enabled", "true")
                                    $xmlWriter.WriteElementString("Address", $sourceDomainComputerItem)
                                    $xmlWriter.WriteEndElement() # Closing EventSourc
                                }
                                $xmlWriter.WriteEndElement() # Closing EventSource
                            }

                            # End the XML Document
                            $xmlWriter.WriteEndDocument()

                            # Finish The Document
                            $xmlWriter.Finalize
                            $xmlWriter.Flush()
                            $xmlWriter.Close()
                        }
                        if($ErrorReturn) { Write-Error "" -ErrorAction Stop }
                    } catch {
                        Stop-PSFFunction -Message "Error on creating temporary configuration file for subscription '$($nameItem)' on computer '$($computer)'." -Target $computer -EnableException $true
                    }

                    # Create subscription from config file in temp folder
                    try {
                        Write-PSFMessage -Level Verbose -Message "Create-subscription with wecutil.exe from temporary config file." -Target $computer
                        $invokeOutput = Invoke-PSFCommand @invokeParams -ScriptBlock {
                            try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { Write-Information -MessageData "Exception while setting UTF8 OutputEncoding. Continue script." }
                            $output = . "$env:windir\system32\wecutil.exe" "create-subscription" "$env:TEMP\$( $args[1] )" *>&1
                            $output = $output | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' } *>&1
                            if($output) { Write-Error -Message "$([string]::Join(" ", $output.Exception.Message.Replace("`r`n"," ")))" -ErrorAction Stop }
                        }
                        if($invokeOutput) {
                            $ErrorReturn = $invokeOutput
                        }
                        if($ErrorReturn) { Write-Error -Message "" -ErrorAction Stop}
                    } catch {
                        # Avoid query for output object at the end of the function
                        $QuerySubscription = $false

                        $ErrorReturnWEC = $ErrorReturn | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' } | select-object -Unique
                        if($ErrorReturnWEC) {
                            # this happens when run in local runspace
                            $ErrorMsg = [string]::Join(" ", ($ErrorReturnWEC.Exception.Message.Replace("`r`n"," ") | select-object -Unique))
                        } else {
                            # this happens when run in remote runspace
                            $ErrorMsg = [string]::Join(" ", ($ErrorReturn.Exception.Message | select-object -Unique))
                        }

                        switch ($ErrorMsg) {
                            "*Error = *" {
                                $ErrorCode = ($ErrorMsg -Split "Error = ")[1].split(".")[0]
                            }
                            { $_ -like "Warning: *" -or $_ -like "Warnung: *" } {
                                $ErrorCode = "Warn1"
                            }
                            Default { $ErrorCode = 0 }
                        }

                        switch ($ErrorCode) {
                            "0x3ae8" {
                                # The subscription is saved successfully, but it can't be activated at this time. Use retry-subscription command to retry the subscription. If subscription is running, you can also use get-subscriptionruntimestatus command to get extended error status. Error = 0x3ae8. The subscription fails to activate.
                                Write-PSFMessage -Level Warning -Message "Warning creating subscription! wecutil.exe message: $($ErrorMsg)" -Target $computer
                            }
                            "Warn1" {
                                Write-PSFMessage -Level Warning -Message "Warning creating subscription! wecutil.exe message: $($ErrorMsg)" -Target $computer
                            }
                            Default { Write-PSFMessage -Level Warning -Message "Error creating subscription '$($nameItem)' on computer '$($computer)'! wecutil.exe message: $($ErrorMsg)(config file: $($invokeParams.ArgumentList[1]))" -Target $computer -EnableException $true }
                        }
                        Remove-Variable -Name ErrorReturn, ErrorReturnWEC, ErrorCode, ErrorMsg -Force -Confirm:$false -Verbose:$false -WhatIf:$false
                    }

                    # Cleanup the xml garbage (temp file)
                    try {
                        Write-PSFMessage -Level Verbose -Message "Operation done. Going to delete temp stuff" -Target $computer
                        Invoke-PSFCommand @invokeParams -ScriptBlock {
                            # xmlFilePath is known in session from the previous executed commands. Path needs to be rebuild when running in local session, maybe.
                            if(-not $xmlFilePath) { $xmlFilePath = $env:TEMP + "\" + $args[1] }
                            Get-ChildItem -Path $xmlFilePath | Remove-Item  -Force -Confirm:$false
                        }
                        if($ErrorReturn) { Write-Error -Message "" -ErrorAction Stop}
                    } catch {
                        Stop-PSFFunction -Message "Error deleting temp files! $($ErrorReturn)" -ErrorRecord $ErrorReturn -Target $computer -EnableException $true -Continue
                    }

                    if($QuerySubscription) {
                        try {
                            Write-PSFMessage -Level Verbose -Message "Query newly created subscription for output" -Target $computer
                            $output = Get-WEFSubscription -Name $nameItem -ComputerName $computer -ErrorAction Stop -ErrorVariable "ErrorReturn"
                            if($output) { $output } else { Write-Error "" -ErrorAction Stop}
                        } catch {
                            Write-PSFMessage -Level Warning -Message "Error finding subscription '$($nameItem)' on computer $computer" -Target $computer -ErrorRecord $_ -EnableException $true
                        }
                    }
                }
            }
            #endregion Processing Events
        }
    }

    End {
    }
}