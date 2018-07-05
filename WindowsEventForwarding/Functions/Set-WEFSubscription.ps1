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
        #[System.Management.Automation.PSCustomObject]
        #[WEF.Subscription.SourceInitiated]
        #[WEF.Subscription]
        $InputObject,

        [Parameter(ValueFromPipeline = $false, Position = 0, Mandatory = $true, ParameterSetName = "ComputerName")]
        [Parameter(ValueFromPipeline = $false, Position = 0, Mandatory = $true, ParameterSetName = "Session")]
        [Alias("DisplayName", "SubscriptionID", "Idendity")]
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
        $Expires
    )
    
    Begin {
        # If session parameter is used -> transfer it to ComputerName,
        # The class "PSFComputer" from PSFramework can handle it. This simplifies the handling in the further process block 
        if ($Session) { $ComputerName = $Session }

        #$nameBound = Test-PSFParameterBinding -ParameterName Name
        #$computerBound = Test-PSFParameterBinding -ParameterName ComputerName
    }

    Process {
        Write-PSFMessage -Level Debug -Message "ParameterNameSet: $($PsCmdlet.ParameterSetName)"

        #region parameterset workarround
        # Workarround parameter binding behaviour of powershell in combination with ComputerName Piping
        #if (-not ($nameBound -or $computerBound) -and $ComputerName.InputObject -and $PSCmdlet.ParameterSetName -ne "Session") {
        #    if ($ComputerName.InputObject -is [string]) { $ComputerName = $env:ComputerName } else { $Name = "" }
        #}
        #endregion parameterset workarround

        #region query specified subscription when not piped in
        if($PsCmdlet.ParameterSetName -ne "InputObject") {
            # when not inputobject --> query for existing object to modify 
            Write-PSFMessage -Level Verbose -Message "Gathering $ComputerName for subscription $Name"
            $InputObject = Get-WEFSubscription -Name $Name -ComputerName $ComputerName -ErrorAction Stop
            if (-not $InputObject) {
                $message = "Subscription $Name not found"
                if($ComputerName) { $message = $message + " on " + $ComputerName }
                throw $message 
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
            #endregion Change properties on subscription depending on given parameters (in memory operations)

            #region Change subscription in system
            # Done by creating temporary XML file from subscription in memory, deleting the old subscription, and recreate it from temporary xml file 
            if ($pscmdlet.ShouldProcess("Subscription: $subscriptionNameOld", "Set properties '$( [String]::Join(', ', $propertyNameChangeList) )' on '$($subscription.ComputerName)'.")) {
                Write-PSFMessage -Level Verbose -Message "Set properties '$( [String]::Join(', ', $propertyNameChangeList) )' on '$($subscription.ComputerName)' in subscription $($subscription.Name)" -Target $subscription.ComputerName
                
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
                    Invoke-PSFCommand @invokeParams -ScriptBlock { Set-Content -Path "$env:TEMP\$( $args[2] )" -Value $args[1] -Force -ErrorAction Stop } #tempFileName , xmlcontent 
                } catch {
                    throw "Error creating temp file for subscription!"
                }
                
                # Delete existing subscription. execute wecutil to delete subscription with redirectoing error output
                try {
                    $null = Invoke-PSFCommand @invokeParams -ScriptBlock { 
                        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                        . "$env:windir\system32\wecutil.exe" "delete-subscription" "$($args[0])" 2>&1 
                    }
                    if($ErrorReturn) { Write-Error "" -ErrorAction Stop}
                } catch {
                    Write-PSFMessage -Level Verbose -Message "this should not happen - this will be an unexpected behaviour" -Target $subscription.ComputerName
                    $ErrorReturn = $ErrorReturn | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' }
                    $ErrorMsg = [string]::Join(" ", $ErrorReturn.Exception.Message.Replace("`r`n"," "))
                    throw "Error deleting existing subscription before recreating it! $($ErrorMsg)"
                }

                # Recreate changed subscription. execute wecutil to recreate changed subscription with redirectoing error output
                try {
                    $null = Invoke-PSFCommand @invokeParams -ScriptBlock { 
                        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                        . "$env:windir\system32\wecutil.exe" "create-subscription" "$env:TEMP\$( $args[2] )" 2>&1 
                    }
                    if($ErrorReturn) { Write-Error -Message "" -ErrorAction Stop}
                } catch {
                    $ErrorReturn = $ErrorReturn | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' }
                    $ErrorMsg = [string]::Join(" ", $ErrorReturn.Exception.Message.Replace("`r`n"," "))
                    $ErrorCode = ($ErrorMsg -Split "Error = ")[1].split(".")[0]
                    switch ($ErrorCode) {
                        "0x3ae8" { 
                            Write-PSFMessage -Level Warning -Message "Warning recreating subscription! wecutil.exe message: $($ErrorMsg)" -Target $subscription.ComputerName 
                        }
                        Default { Write-PSFMessage -Level Critical -Message "Error recreating subscription! wecutil.exe message: $($ErrorMsg)" -Target $subscription.ComputerName }
                    }
                    Clear-Variable -Name ErrorReturn -Force
                }

                # Cleanup the xml garbage (temp file)
                if(-not $result) {
                    Write-PSFMessage -Level Verbose -Message "Changes done. Going to delete temp stuff" -Target $subscription.ComputerName
                    Invoke-PSFCommand @invokeParams -ScriptBlock { Remove-Item -Path "$env:TEMP\$( $args[2] )" -Force -Confirm:$false }
                } else { 
                    Write-PSFMessage -Level Critical -Message "Error deleting temp files! $($ErrorReturn)" -Target $subscription.ComputerName
                }
            }
            #endregion Change subscription in system
        }
    }

    End {
    }
}