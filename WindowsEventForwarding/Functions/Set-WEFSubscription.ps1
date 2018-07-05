function Set-WEFSubscription {
    <#
        .Synopsis
        Set-WEFSubscription

        .DESCRIPTION
        Set properties on a Windows Eventlog Forwarding subscription 

        .NOTES
        Author: Andreas Bellstedt

        .LINK
        https://github.com/AndiBellstedt/WindowsEventForwarding

        .EXAMPLE
        Set-WEFSubscription
        Example text 

    #>
    [CmdletBinding( DefaultParameterSetName = 'ComputerName',
        SupportsShouldProcess = $true,
        ConfirmImpact = 'medium')]
    Param(
        [Parameter(ValueFromPipeline = $true, Position = 0, ParameterSetName = "InputObject", Mandatory=$true)]
        #[System.Management.Automation.PSCustomObject]
        $InputObject,

        [Parameter(ValueFromPipeline = $true, Position = 0, ParameterSetName = "Session")]
        [Parameter(ValueFromPipeline = $true, Position = 0, ParameterSetName = "Name")]
        [Parameter(ValueFromPipeline = $false, Position = 0, ParameterSetName = "ComputerName")]
        [Alias("DisplayName", "SubscriptionID", "Idendity")]
        [String]
        $Name,

        [Parameter(ValueFromPipeline = $true, Position = 1, ParameterSetName = "ComputerName")]
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

        [ValidateSet("en-US", "de-DE", "fr-FR", "es-ES", "nl-NL","it-IT")]
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

        [ValidateNotNullOrEmpty()]
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
    }

    Process {
        Write-PSFMessage -Level Verbose -Message "ParameterNameSet: $($PsCmdlet.ParameterSetName)"

        # Workarround parameter binding behaviour of powershell in combination with ComputerName Piping
        if (-not ($nameBound -or $computerBound) -and $ComputerName.InputObject -and $PSCmdlet.ParameterSetName -ne "Session") {
            if ($ComputerName.InputObject -is [string]) { $ComputerName = $env:ComputerName } else { $Name = "" }
        }
        
        # Checking Parameterset - when not inputobject query for existiing object to modiy 
        if($PsCmdlet.ParameterSetName -ne "InputObject") {
            Write-PSFMessage -Level Verbose -Message "Gathering $ComputerName for subscription $Name"
            $InputObject = Get-WEFSubscription -Name $Name -ComputerName $ComputerName -ErrorAction Stop
            if (-not $InputObject) {
                $message = "Subscription $Name not found"
                if($ComputerName) { $message = $message + " on " + $ComputerName }
                throw $message 
            }
        }

        foreach ($subscription in $InputObject) {
            #region Connecting and gathering prerequisites
            Write-PSFMessage -Level Verbose -Message "Processing $($subscription.Name) on $($subscription.ComputerName)" -Target $subscription.ComputerName
            
            # keep original name to identify existing subscription later 
            $subscriptionNameOld = $subscription.Name

            # Change properties depending on given parameters
            
            $propertyNameChangeList = @()
            switch ($PSBoundParameters.Keys) {
                "NewName" { 
                    $propertyNameChangeList += "NewName"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'NewName'"

                    $subscription.BaseObject.Subscription.SubscriptionId = $NewName #+((get-date -Format s).ToString().Replace(":","").Replace(".",""))  # for testing
                }
                "Description" {
                    $propertyNameChangeList += "Description"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Description'"

                    $subscription.BaseObject.Subscription.Description = $Description 
                }
                "Enabled" {
                    $propertyNameChangeList += "Enabled"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Enabled'"

                    $subscription.BaseObject.Subscription.Enabled = $Enabled.ToString() 
                }
                "ReadExistingEvents" {
                    $propertyNameChangeList += "ReadExistingEvents"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'ReadExistingEvents'"

                    $subscription.BaseObject.Subscription.ReadExistingEvents = $ReadExistingEvents.ToString() 
                }
                "ContentFormat" {
                    $propertyNameChangeList += "ContentFormat"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'ContentFormat'"

                    $subscription.BaseObject.Subscription.ContentFormat = $ContentFormat 
                }
                "LogFile" {
                    $propertyNameChangeList += "LogFile"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'LogFile'"

                    $subscription.BaseObject.Subscription.LogFile = $LogFile 
                }
                "Locale" { 
                    $propertyNameChangeList += "Locale"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Locale'"

                    $subscription.BaseObject.Subscription.Locale.Language = $Locale
                }
                "Query" {
                    $propertyNameChangeList += "Query"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Query'"

                    # Build the XML string to insert the query
                    $queryString = "<![CDATA[<QueryList> <Query Id='0'>"
                    foreach ($queryItem in $Query) {
                        $queryString += "`n" + $queryItem
                    }
                    $queryString += "`n" + "</Query></QueryList>]]>"

                    # Insert the new query in the subscription 
                    $subscription.BaseObject.Subscription.Query.InnerXml = $queryString

                    # Cleanup the mess
                    Remove-Variable -Name queryString -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 
                }
                "MaxLatency" {
                    $propertyNameChangeList += "MaxLatency"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'MaxLatency'"

                    $subscription.BaseObject.Subscription.ConfigurationMode = "Custom"
                    $subscription.BaseObject.Subscription.Delivery.Batching.MaxLatencyTime = $MaxLatency.TotalMilliseconds.ToString() 
                }
                "HeartBeatInterval" {
                    $propertyNameChangeList += "HeartBeatInterval"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'HeartBeatInterval'"

                    $subscription.BaseObject.Subscription.ConfigurationMode = "Custom"
                    $subscription.BaseObject.Subscription.Delivery.PushSettings.Heartbeat.Interval = $HeartBeatInterval.TotalMilliseconds.ToString() 
                }
                "MaxItems" {
                    $propertyNameChangeList += "MaxItems"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'MaxItems'"

                    $subscription.BaseObject.Subscription.ConfigurationMode = "Custom"
                    if(-not ($subscription.BaseObject.Subscription.Delivery.Batching.MaxItems| Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.Delivery.Batching.InnerXml = $subscription.BaseObject.Subscription.Delivery.Batching.InnerXml + '<MaxItems xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"></MaxItems>'
                    }
                    $subscription.BaseObject.Subscription.Delivery.Batching.MaxItems = $MaxItems.ToString() 
                }
                "TransportName" {
                    $propertyNameChangeList += "TransportName"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'TransportName'"

                    $subscription.BaseObject.Subscription.TransportName = $TransportName 
                }
                "SourceDomainComputer" {
                    $propertyNameChangeList += "SourceDomainComputer"
                    Write-PSFMessage -Level Warning -Message "modifying SourceDomainComputer is not support yet"

                    # not support yet
                }
                "SourceNonDomainDNSList" {
                    $propertyNameChangeList += "SourceNonDomainDNSList"
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'SourceNonDomainDNSList' (AllowedSubjectList)"

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
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'SourceNonDomainIssuerCAThumbprint' (AllowedIssuerCAList)"
                    
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
                    Write-PSFMessage -Level Verbose -Message "Modifying property 'Expires'"

                    if(-not ($subscription.BaseObject.Subscription.Expires | Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.InnerXml = $subscription.BaseObject.Subscription.InnerXml + '<Expires xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"></Expires>'
                    }
                    $subscription.BaseObject.Subscription.Expires = ($Expires | Get-Date -Format s).ToString()
                }
                Default { }
            }

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
                        Default { Write-PSFMessage -Level Error -Message "Error recreating subscription! wecutil.exe message: $($ErrorMsg)" -Target $subscription.ComputerName }
                    }
                    Clear-Variable -Name ErrorReturn -Force
                }

                # Cleanup the xml garbage (temp file)
                if(-not $result) {
                    Write-PSFMessage -Level Verbose -Message "Changes done. Going to delete temp stuff" -Target $subscription.ComputerName
                    Invoke-PSFCommand @invokeParams -ScriptBlock { Remove-Item -Path "$env:TEMP\$( $args[2] )" -Force -Confirm:$false }
                } else { 
                    Write-PSFMessage -Level Error -Message "Error deleting temp files! $($ErrorReturn)" -Target $subscription.ComputerName
                }
            }
        }
    }

    End {
        # Clearing up the mess of variables
        #Remove-Variable -Name TypeName -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}