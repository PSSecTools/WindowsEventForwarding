function New-WEFSubscription {
    <#
        .Synopsis
            New-WEFSubscription

        .DESCRIPTION
            Create a new Windows Eventlog Forwarding subscription(s).

        .PARAMETER ComputerName
            The computer(s) to connect to.
            Supports PSSession objects, will reuse sessions.

        .PARAMETER Name
            Name of the subscription to filter by.

        .PARAMETER Type
            The type of the subscription


        .EXAMPLE
            PS C:\> New-WEFSubscription -Name "MySubscription"
            
            Create a new subscription "MySubScription"

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

            # Check service 'Windows Event Collector' - without this, there are not subscriptions possible
            Write-PSFMessage -Level Verbose -Message "Checking service 'Windows Event Collector'" -Target $computer
            $service = Invoke-PSFCommand -ComputerName $computer -ScriptBlock { Get-Service -Name "wecsvc" } -ErrorAction Stop
            if ($service.Status -ne 'Running') {
                Stop-PSFFunction -Message "Working with eventlog subscriptions requires  the 'Windows Event Collector' service in running state.  Please ensure that the service is set up correctly or use 'wecutil.exe qc'."
                return
            }

            if(-not (Invoke-PSFCommand -ComputerName $computer -ScriptBlock { Get-WinEvent -ListLog $using:LogFile })) {
                Stop-PSFFunction -Message "Eventlog '$($LogFile)' not found on computer '$($computer)'. Aborting creation of subscription."
                return
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
                    Write-PSFMessage -Level Verbose -Message "Create subscription '$($nameItem)' on computer '$($computer)'" -Target $computer
                    
                    # Write XML config file in temp folder  
                    try {
                        Write-PSFMessage -Level Verbose -Message "Create temporary config file '$($invokeParams.ArgumentList[1])' for new subscription" -Target $computer
                        $null = Invoke-PSFCommand @invokeParams -ScriptBlock {
                            $subscriptionProperties = $args[0]

                            # Create our new XML File	
                            $xmlFilePath = $env:TEMP + "\" +$args[1]
                            $XmlWriter = New-Object System.XMl.XmlTextWriter($xmlFilePath, $null)

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
                            $xmlWriter.WriteStartElement("Delivery") # Start Delivery
                            $xmlWriter.WriteAttributeString("Mode", $subscriptionProperties.Mode)
                            $xmlWriter.WriteStartElement("Batching") # Start Batching
                            $xmlWriter.WriteElementString("MaxLatencyTime", $subscriptionProperties.MaxLatency.TotalMilliseconds)
                            $xmlWriter.WriteEndElement() # Close Batching
                            $xmlWriter.WriteStartElement("PushSettings") # Start PushSettings
                            $xmlWriter.WriteStartElement("Heartbeat") # Start Heartbeat
                            $xmlWriter.WriteAttributeString("Interval", $subscriptionProperties.HeartBeatInterval.TotalMilliseconds)
                            $xmlWriter.WriteEndElement() # Closing Heartbeat
                            $xmlWriter.WriteEndElement() # Closing PushSettings
                            $xmlWriter.WriteEndElement() # Closing Delivery
                            $xmlWriter.WriteStartElement("Query") # Start Query
                            $xmlWriter.WriteCData("<QueryList> <Query Id='0'>`r`t$( [string]::Join("`r`t", $subscriptionProperties.Query) )`r</Query></QueryList>")
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
                        Write-PSFMessage -Level Verbose -Message "Error on create subscription." -Target $computer
                        $ErrorReturn = $ErrorReturn | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' }
                        $ErrorMsg = [string]::Join(" ", $ErrorReturn.Exception.Message.Replace("`r`n"," "))
                        throw "Error creating subscription '$($nameItem)' on computer '$($computer)'! $($ErrorMsg)"    
                    }
                }
            }
            #endregion Processing Events
        }
    }

    End {
    }
}