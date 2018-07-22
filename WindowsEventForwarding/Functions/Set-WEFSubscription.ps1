function Set-WEFSubscription {
    <#
        .Synopsis
            Set-WEFSubscription

        .DESCRIPTION
            Set properties on a Windows Eventlog Forwarding subscription

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

        .PARAMETER NewName
            The new name for the subscription.

        .PARAMETER Description
            The discription for a subscription.

        .PARAMETER Enabled
            Set the status of a subscription.

            Available aliases: "Enable" and "Status"

        .PARAMETER ReadExistingEvents
            Specifies which kind of events are transfered.
            If set TRUE, all events will be transfered. If set to false,
            only newly created events will be transfered.

        .PARAMETER ContentFormat
            Can be set to "Events" or "RenderedText".
            This setting specifies, how events are transfered and rendered
            to server.
            If setting is "RenderedText", the events will be rendered in the
            localization from the client. If setting is "Events", the
            interpreting of the events will be done on the server.

        .PARAMETER Locale
            Localization schema for events.
            Setting only apply when ContentFormat is "RenderedText".
            <String>

        .PARAMETER LogFile
            Name of the eventlog where to store the forwarded events.

        .PARAMETER Query
            Query string(s) which events will be included in the subscription.
            Only the "Select"-part of the query has to be specified.

            Example:
            '<Select Path="System">*[System[(Level=1  or Level=2 or Level=3)]]</Select>'

        .PARAMETER MaxLatency
            Maximum latency interval in milliseconds while forwarding events.

        .PARAMETER HeartBeatInterval
            Heartbeat interval in milliseconds.

        .PARAMETER MaxItems
            Amount of maxium events per interval to transfer.

        .PARAMETER TransportName
            Type of connection for transfering events. Possible values are "http" or "https".
            (data is always encrypted, event when transfer mode is "http", which is the default)

        .PARAMETER SourceDomainComputer
            Name(s) and/or SID(s) of computers or groups, to apply on the subscription.

            Example:
            "Domain computers", "Domain controllers", "MyComputerGroup"
            "S-1-5-21-1234567890-12345678-123456789-515", "S-1-5-21-1234567890-12345678-123456789-516"

        .PARAMETER SourceNonDomainDNSList
            Name(s) of DNS match list.

            Example:
            "*.mydomain.com"

        .PARAMETER SourceNonDomainIssuerCAThumbprint
            Certificate thumbprint(s) of trusted certificate authority..

            Example:
            "100F1CAED645BB78B3EA2B94C0697C7407330010"

        .PARAMETER Expires
            Specifies a datetime when the subscription expires and computers will be no more active.

        .EXAMPLE
            PS C:\> Set-WEFSubscription -Name "Subscription1" -NewName "Subscription1New"

            Rename the subscription "Subscription1" to "Subscription1New"

        .EXAMPLE
            PS C:\> Get-WEFSubscription -Name "Subscription1" | Set-WEFSubscription -Enabled $true

            Enable "Subscription1" by using the pipeline.
            Aliases "Enable" and "Status" available for parameter "Enabled".

        .EXAMPLE
            PS C:\> Set-WEFSubscription -Name "MySubscription" -ComputerName "SERVER1" -Enabled $true -ReadExistingEvents $true -Query '<Select Path="System">*[System[(Level=1  or Level=2 or Level=3)]]</Select>' -Description "This is my subscription" -SourceDomainComputer "Domain controllers", "MyComputerGroup"

            Enable "MySubscription" and set properties.

        .NOTES
            Author: Andreas Bellstedt

        .LINK
            https://github.com/AndiBellstedt/WindowsEventForwarding
    #>
    [CmdletBinding( DefaultParameterSetName = 'ComputerName',
        SupportsShouldProcess = $true,
        ConfirmImpact = 'medium')]
    Param(
        [Parameter(ValueFromPipeline = $true, Position = 0, ParameterSetName = "InputObject")]
        [WEF.Subscription[]]
        $InputObject,

        [Parameter(ValueFromPipeline = $false, Position = 0, Mandatory = $false, ParameterSetName = "ComputerName")]
        [Parameter(ValueFromPipeline = $false, Position = 0, Mandatory = $false, ParameterSetName = "Session")]
        [Alias("DisplayName", "SubscriptionID", "Idendity")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name,

        [Parameter(ValueFromPipeline = $true, Position = 1, Mandatory = $false, ParameterSetName = "ComputerName")]
        [Alias("host", "hostname", "Computer", "DNSHostName")]
        [PSFComputer[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = "Session")]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [PSCredential]
        $Credential,

        [ValidateNotNullOrEmpty()]
        [String]
        $NewName,

        [ValidateNotNullOrEmpty()]
        [string]
        $Description,

        [Alias("Enable", "Status")]
        [bool]
        $Enabled,

        [bool]
        $ReadExistingEvents,

        [ValidateSet("Events", "RenderedText")]
        [string]
        $ContentFormat,

        [ValidateNotNullOrEmpty()]
        [string]
        $LogFile,

        [ValidateSet("en-US", "de-DE", "fr-FR", "es-ES", "nl-NL","it-IT","af-ZA","cs-CZ","en-GB","en-NZ","en-TT","es-PR","ko-KR","sk-SK","zh-CN","zh-HK")]
        [string]
        $Locale,

        [ValidateNotNullOrEmpty()]
        [string[]]
        $Query,

        [ValidateNotNullOrEmpty()]
        [timespan]
        $MaxLatency,

        [ValidateNotNullOrEmpty()]
        [timespan]
        $HeartBeatInterval,

        [ValidateNotNullOrEmpty()]
        [int]
        $MaxItems,

        [ValidateSet("HTTP", "HTTPS")]
        [string]
        $TransportName,

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
        $Expires,

        [switch]
        $PassThru
    )

    Begin {
        # If session parameter is used -> transfer it to ComputerName,
        # The class "PSFComputer" from PSFramework can handle it. This simplifies the handling in the further process block
        if ($Session) { $ComputerName = $Session }
    }

    Process {
        Write-PSFMessage -Level Debug -Message "ParameterNameSet: $($PsCmdlet.ParameterSetName)"

        #region query specified subscription when not piped in
        if($PsCmdlet.ParameterSetName -ne "InputObject") {
            # when not inputobject --> query for existing object to modify
            Write-PSFMessage -Level Verbose -Message "Gathering $ComputerName for subscription $Name"
            try {
                $InputObject = Get-WEFSubscription -Name $Name -ComputerName $ComputerName -ErrorAction Stop
            } catch {
                Stop-PSFFunction -Message "Error finding subscription '$name' on computer $computer" -ErrorRecord $_
            }
            if (-not $InputObject) {
                $message = "Subscription $Name not found"
                if($ComputerName) { $message = $message + " on " + $ComputerName }
                Stop-PSFFunction -Message $message
            }
        }
        #endregion query specified subscription when not piped in

        foreach ($subscription in $InputObject) {
            Write-PSFMessage -Level Verbose -Message "Processing $($subscription.Name) on $($subscription.ComputerName)" -Target $subscription.ComputerName
            #region preparation
            # Keep original name to identify existing subscription later
            $subscriptionNameOld = $subscription.Name
            #endregion preparation

            #region Change properties on subscription depending on given parameters (in memory operations)
            $propertyNameChangeList = @()
            switch ($PSBoundParameters.Keys) {
                "NewName" {
                    $propertyNameChangeList += "NewName"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'NewName'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.SubscriptionId = $NewName #+((get-date -Format s).ToString().Replace(":","").Replace(".",""))  # for testing
                }

                "Description" {
                    $propertyNameChangeList += "Description"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Description'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.Description = $Description
                }

                "Enabled" {
                    $propertyNameChangeList += "Enabled"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Enabled'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.Enabled = $Enabled.ToString()
                }

                "ReadExistingEvents" {
                    $propertyNameChangeList += "ReadExistingEvents"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'ReadExistingEvents'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.ReadExistingEvents = $ReadExistingEvents.ToString()
                }

                "ContentFormat" {
                    $propertyNameChangeList += "ContentFormat"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'ContentFormat'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.ContentFormat = $ContentFormat
                }

                "LogFile" {
                    $propertyNameChangeList += "LogFile"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'LogFile'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.LogFile = $LogFile
                }

                "Locale" {
                    $propertyNameChangeList += "Locale"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Locale'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.Locale.Language = $Locale
                }

                "Query" {
                    $propertyNameChangeList += "Query"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Query'" -Target $subscription.ComputerName

                    # Build the XML string to insert the query
                    $queryString = "<![CDATA[<QueryList> <Query Id='0'>`r`t$( [string]::Join("`r`t", $Query) )`r</Query></QueryList>]]>"

                    # Insert the new query in the subscription
                    $subscription.BaseObject.Subscription.Query.InnerXml = $queryString

                    # Cleanup the mess
                    Remove-Variable -Name queryString -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                }

                "MaxLatency" {
                    $propertyNameChangeList += "MaxLatency"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'MaxLatency'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.ConfigurationMode = "Custom"
                    $subscription.BaseObject.Subscription.Delivery.Batching.MaxLatencyTime = $MaxLatency.TotalMilliseconds.ToString()
                }

                "HeartBeatInterval" {
                    $propertyNameChangeList += "HeartBeatInterval"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'HeartBeatInterval'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.ConfigurationMode = "Custom"
                    $subscription.BaseObject.Subscription.Delivery.PushSettings.Heartbeat.Interval = $HeartBeatInterval.TotalMilliseconds.ToString()
                }

                "MaxItems" {
                    $propertyNameChangeList += "MaxItems"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'MaxItems'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.ConfigurationMode = "Custom"
                    if(-not ($subscription.BaseObject.Subscription.Delivery.Batching.MaxItems| Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.Delivery.Batching.InnerXml = $subscription.BaseObject.Subscription.Delivery.Batching.InnerXml + '<MaxItems xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"></MaxItems>'
                    }
                    $subscription.BaseObject.Subscription.Delivery.Batching.MaxItems = $MaxItems.ToString()
                }

                "TransportName" {
                    $propertyNameChangeList += "TransportName"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'TransportName'" -Target $subscription.ComputerName

                    $subscription.BaseObject.Subscription.TransportName = $TransportName
                }

                "SourceDomainComputer" {
                    $propertyNameChangeList += "SourceDomainComputer"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'SourceDomainComputer'" -Target $subscription.ComputerName
                    # not support yet

                    # check if property "AllowedSourceDomainComputers" exist
                    $dummyProperty = '<AllowedSourceDomainComputers xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"></AllowedSourceDomainComputers>'
                    if(-not ($subscription.BaseObject.Subscription.AllowedSourceDomainComputers | Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.InnerXml = $subscription.BaseObject.Subscription.InnerXml + $dummyProperty
                    }

                    # Parse every value specified, translate from name to SID
                    $sddlString = "O:NSG:BAD:P"
                    foreach ($sourceDomainComputerItem in $SourceDomainComputer) {
                        if($sourceDomainComputerItem -match 'S-1-5-21-(\d|-)*$') {
                            # sourceDomainComputerItem is a SID, no need to translate
                            $SID = $sourceDomainComputerItem
                        } else {
                            # try to translate name to SID
                            try {
                                $SID = [System.Security.Principal.NTAccount]::new( $sourceDomainComputerItem ).Translate([System.Security.Principal.SecurityIdentifier]).Value
                            } catch {
                                Write-PSFMessage -Level Critical -Message "Cannot convert '$sourceDomainComputerItem' to a valid SID! '$sourceDomainComputerItem' will not be included as SourceDomainComputer in subscription." -Target $subscription.ComputerName
                                break
                            }
                        }

                        # Insert SDDL-String with SID
                        $sddlString = $sddlString + "(A;;GA;;;" + $SID + ")"
                    }
                    $sddlString = $sddlString + "S:"
                    $subscription.BaseObject.Subscription.AllowedSourceDomainComputers = $sddlString

                    # cleanup temporary vaiables
                    Remove-Variable -Name dummyProperty, SID, sddlString -Force -Confirm:$false
                }

                "SourceNonDomainDNSList" {
                    $propertyNameChangeList += "SourceNonDomainDNSList"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'SourceNonDomainDNSList' (AllowedSubjectList)" -Target $subscription.ComputerName

                    # check if property "AllowedSourceNonDomainComputers" exist
                    $dummyProperty = '<AllowedSourceNonDomainComputers xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><AllowedIssuerCAList><IssuerCA></IssuerCA></AllowedIssuerCAList><AllowedSubjectList><Subject></Subject></AllowedSubjectList></AllowedSourceNonDomainComputers>'
                    if(-not ($subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers | Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.InnerXml = $subscription.BaseObject.Subscription.InnerXml + $dummyProperty
                    } elseif ($subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.pstypenames -contains "System.String") {
                        $subscription.BaseObject.Subscription.InnerXml = $subscription.BaseObject.Subscription.InnerXml -replace '<AllowedSourceNonDomainComputers xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"></AllowedSourceNonDomainComputers>', $dummyProperty
                    }

                    # check if property "AllowedSubjectList" exist
                    if(-not ($subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.AllowedSubjectList | Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.InnerXml = $subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.InnerXml + '<AllowedSubjectList xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><Subject></Subject></AllowedSubjectList>'
                    }

                    # build XML and set property
                    $xmlText = ""
                    foreach ($dnsItem in $SourceNonDomainDNSList) {
                        $xmlText += "<Subject xmlns=""http://schemas.microsoft.com/2006/03/windows/events/subscription"">$($dnsItem)</Subject>"
                    }
                    $subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.AllowedSubjectList.InnerXml = $xmlText

                    # cleanup temporary vaiables
                    Remove-Variable -Name dummyProperty, xmlText -Force -Confirm:$false
                }

                "SourceNonDomainIssuerCAThumbprint" {
                    $propertyNameChangeList += "SourceNonDomainIssuerCAThumbprint"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'SourceNonDomainIssuerCAThumbprint' (AllowedIssuerCAList)" -Target $subscription.ComputerName

                    # check if property "AllowedSourceNonDomainComputers" exist
                    $dummyProperty = '<AllowedSourceNonDomainComputers xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><AllowedIssuerCAList><IssuerCA></IssuerCA></AllowedIssuerCAList><AllowedSubjectList><Subject></Subject></AllowedSubjectList></AllowedSourceNonDomainComputers>'
                    if(-not ($subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers | Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.InnerXml = $subscription.BaseObject.Subscription.InnerXml + $dummyProperty
                    } elseif ($subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.pstypenames -contains "System.String") {
                        $subscription.BaseObject.Subscription.InnerXml = $subscription.BaseObject.Subscription.InnerXml -replace '<AllowedSourceNonDomainComputers xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"></AllowedSourceNonDomainComputers>', $dummyProperty
                    }

                    # check if property "AllowedIssuerCAList" exist
                    if(-not ($subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.AllowedIssuerCAList | Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.InnerXml = $subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.InnerXml + '<AllowedIssuerCAList xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><IssuerCA></IssuerCA></AllowedIssuerCAList>'
                    }

                    # build XML and set property
                    $xmlText = ""
                    foreach ($thumbprint in $SourceNonDomainIssuerCAThumbprint) {
                        $xmlText += "<IssuerCA xmlns=""http://schemas.microsoft.com/2006/03/windows/events/subscription"">$($thumbprint)</IssuerCA>"
                    }
                    $subscription.BaseObject.Subscription.AllowedSourceNonDomainComputers.AllowedIssuerCAList.InnerXml = $xmlText

                    # cleanup temporary vaiables
                    Remove-Variable -Name dummyProperty, xmlText -Force -Confirm:$false
                }

                "Expires" {
                    $propertyNameChangeList += "Expires"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Expires'" -Target $subscription.ComputerName

                    if(-not ($subscription.BaseObject.Subscription.Expires | Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.InnerXml = $subscription.BaseObject.Subscription.InnerXml + '<Expires xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"></Expires>'
                    }
                    $subscription.BaseObject.Subscription.Expires = ($Expires | Get-Date -Format s).ToString()
                }

                Default { }
            }

            if($propertyNameChangeList -contains "Locale" -and $subscription.BaseObject.Subscription.ContentFormat -ne "RenderedText") {
                Write-PSFMessage -Level Important -Message "Property 'Locale' is specified, but 'ContentFormat' is not set to 'RenderedText'. Property setting done, but without effect." -Target $subscription.ComputerName
            }
            #endregion Change properties on subscription depending on given parameters (in memory operations)

            #region Change subscription in system
            # Done by creating temporary XML file from subscription in memory, deleting the old subscription, and recreate it from temporary xml file
            if ($pscmdlet.ShouldProcess("Subscription: $subscriptionNameOld", "Set properties '$( [String]::Join(', ', $propertyNameChangeList) )' on '$($subscription.ComputerName)'.")) {
                Write-PSFMessage -Level Verbose -Message "Start setting properties '$( [String]::Join(', ', $propertyNameChangeList) )' on '$($subscription.ComputerName)' in subscription '$($subscription.Name)'" -Target $subscription.ComputerName

                $invokeParams = @{
                    ComputerName  = $subscription.ComputerName
                    ErrorAction   = "Stop"
                    ErrorVariable = "ErrorReturn"
                    ArgumentList  = @(
                        $subscriptionNameOld,
                        $subscription.BaseObject.InnerXml,
                        "WEF.$( [system.guid]::newguid().guid ).xml"
                    )
                }
                if($Credential) { $invokeParams.Add("Credential", $Credential)}

                # Create temp file name
                try {
                    Write-PSFMessage -Level Verbose -Message "Create temporary config file '$($invokeParams.ArgumentList[2])' for subscription to be changed." -Target $subscription.ComputerName
                    Invoke-PSFCommand @invokeParams -ScriptBlock { Set-Content -Path "$env:TEMP\$( $args[2] )" -Value $args[1] -Force -ErrorAction Stop } #tempFileName , xmlcontent
                } catch {
                    Stop-PSFFunction -Message "Error creating temp file for subscription!" -ErrorRecord $_ -EnableException $true
                }

                # Delete existing subscription. execute wecutil to delete subscription with redirecting error output
                try {
                    Write-PSFMessage -Level Verbose -Message "Delete existing subscription with wecutil.exe." -Target $subscription.ComputerName
                    $invokeOutput = Invoke-PSFCommand @invokeParams -ScriptBlock {
                        try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
                        $output = . "$env:windir\system32\wecutil.exe" "delete-subscription" "$($args[0])" *>&1
                        $output = $output | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' } *>&1
                        if($output) { Write-Error -Message "$([string]::Join(" ", $output.Exception.Message.Replace("`r`n"," ")))" -ErrorAction Stop }
                    }
                    if($ErrorReturn) { Write-Error "" -ErrorAction Stop}
                } catch {
                    Write-PSFMessage -Level Verbose -Message "This should not happen - unexpected behaviour!" -Target $subscription.ComputerName

                    $ErrorReturnWEC = $ErrorReturn | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' } | select-object -Unique
                    if($ErrorReturnWEC) {
                        $ErrorMsg = [string]::Join(" ", ($ErrorReturnWEC.Exception.Message.Replace("`r`n"," ") | select-object -Unique))
                    } else {
                        $ErrorMsg = [string]::Join(" ", ($ErrorReturn.Exception.Message | select-object -Unique))
                    }

                    Stop-PSFFunction -Message "Error deleting existing subscription before recreating it! $($ErrorMsg)" -ErrorRecord $_ -EnableException $true
                }

                # Recreate changed subscription. execute wecutil to recreate changed subscription with redirecting error output
                $ErrorReturn = $null
                try {
                    Write-PSFMessage -Level Verbose -Message "Recreate subscription with wecutil.exe from temporary config file." -Target $subscription.ComputerName
                    $invokeOutput = Invoke-PSFCommand @invokeParams -ScriptBlock {
                        try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
                        $output = . "$env:windir\system32\wecutil.exe" "create-subscription" "$env:TEMP\$( $args[2] )" *>&1
                        $output = $output | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' } *>&1
                        if($output) { Write-Error -Message "$([string]::Join(" ", $output.Exception.Message.Replace("`r`n"," ")))" -ErrorAction Stop }
                    }
                    if($invokeOutput) { $ErrorReturn += $invokeOutput }
                    if($ErrorReturn) { Write-Error -Message "" -ErrorAction Stop}
                } catch {
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
                        { ($_ -like "Warning: *") -or ($_ -like "Warnung: *") } {
                            $ErrorCode = "Warn1"
                        }
                        { $_ -like "Warning: Configuration mode for the subscription is not Custom.*"} {
                            $ErrorCode = "Warn2"
                        }
                        Default { $ErrorCode = 0 }
                    }

                    switch ($ErrorCode) {
                        {$_ -like "0x3ae8" -or $_ -like "Warn1"} {
                            # 0x3ae8 = The subscription is saved successfully, but it can't be activated at this time. Use retry-subscription command to retry the subscription. If subscription is running, you can also use get-subscriptionruntimestatus command to get extended error status. Error = 0x3ae8. The subscription fails to activate.
                            # Warn1  = wecutil only throw a warning, which means, this is not a critical thing. No Exception needed.
                            Write-PSFMessage -Level Warning -Message "Warning recreating subscription! wecutil.exe message: $($ErrorMsg)" -Target $subscription.ComputerName
                        }
                        "Warn2" {
                            # Warn2  = Warning: Configuration mode for the subscription is not Custom. Delivery properties are not customizable for such mode. As a result, Delivery node from the provided configuration file will be ignored.
                            Write-PSFMessage -Level Verbose -Message "Noncritical warning on recreating of the subscription! wecutil.exe message: $($ErrorMsg)" -Target $subscription.ComputerName
                        }
                        Default { Write-PSFMessage -Level Warning -Message "Error recreating subscription! wecutil.exe message: $($ErrorMsg)" -Target $subscription.ComputerName -EnableException $true}
                    }
                    Clear-Variable -Name ErrorReturn -Force
                }

                # Cleanup the xml garbage (temp file)
                if(-not $result) {
                    Write-PSFMessage -Level Verbose -Message "Changes done. Going to delete temporary config file" -Target $subscription.ComputerName
                    Invoke-PSFCommand @invokeParams -ScriptBlock { Get-ChildItem -Path "$env:TEMP\$( $args[2] )" | Remove-Item -Force -Confirm:$false }
                } else {
                    Write-PSFMessage -Level Warning -Message "Error deleting temp files! $($ErrorReturn)" -Target $subscription.ComputerName -EnableException $true
                }

                if($PassThru) {
                    Write-PSFMessage -Level Verbose -Message "Passthru specified, gathering changed subscription '$($subscription.Name)' on '$ComputerName' again"
                    try {
                        $output = Get-WEFSubscription -Name $subscription.Name -ComputerName $ComputerName -ErrorAction Stop
                        if($output) { $output } else { Write-Error "" -ErrorAction Stop}
                    } catch {
                        Stop-PSFFunction -Message "Error finding subscription '$($subscription.Name)' on computer $computer" -ErrorRecord $_ -EnableException $true
                    }
                }
            }
            #endregion Change subscription in system
        }
    }

    End {
    }
}