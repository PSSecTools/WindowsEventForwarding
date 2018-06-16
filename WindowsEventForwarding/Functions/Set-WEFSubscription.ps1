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

        [ValidateNotNullOrEmpty()]
        [string[]]
        $SourceNonDomainDNSList,

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
                    $subscription.BaseObject.Subscription.SubscriptionId = $NewName #+((get-date -Format s).ToString().Replace(":","").Replace(".",""))  # for testing
                }
                "Description" {
                    $propertyNameChangeList += "Description"
                    $subscription.BaseObject.Subscription.Description = $Description 
                }
                "Enabled" {
                    $propertyNameChangeList += "Enabled"
                    $subscription.BaseObject.Subscription.Enabled = $Enabled.ToString() 
                }
                "ReadExistingEvents" {
                    $propertyNameChangeList += "ReadExistingEvents"
                    $subscription.BaseObject.Subscription.ReadExistingEvents = $ReadExistingEvents.ToString() 
                }
                "ContentFormat" {
                    $propertyNameChangeList += "ContentFormat"
                    $subscription.BaseObject.Subscription.ContentFormat = $ContentFormat 
                }
                "LogFile" {
                    $propertyNameChangeList += "LogFile"
                    $subscription.BaseObject.Subscription.LogFile = $LogFile 
                }
                "Locale" { 
                    $propertyNameChangeList += ""
                    $subscription.BaseObject.Subscription.Locale.Language = $Locale
                }
                "Query" {
                    $propertyNameChangeList += "Query"
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
                    $subscription.BaseObject.Subscription.ConfigurationMode = "Custom"
                    $subscription.BaseObject.Subscription.Delivery.Batching.MaxLatencyTime = $MaxLatency.TotalMilliseconds.ToString() 
                }
                "HeartBeatInterval" {
                    $propertyNameChangeList += "HeartBeatInterval"
                    $subscription.BaseObject.Subscription.ConfigurationMode = "Custom"
                    $subscription.BaseObject.Subscription.Delivery.PushSettings.Heartbeat.Interval = $HeartBeatInterval.TotalMilliseconds.ToString() 
                }
                "MaxItems" {
                    $propertyNameChangeList += "MaxItems"
                    $subscription.BaseObject.Subscription.ConfigurationMode = "Custom"
                    if(-not ($subscription.BaseObject.Subscription.Delivery.Batching.MaxItems| Get-Member -ErrorAction SilentlyContinue)) {
                        $subscription.BaseObject.Subscription.Delivery.Batching.InnerXml = $subscription.BaseObject.Subscription.Delivery.Batching.InnerXml + '<MaxItems xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"></MaxItems>'
                    }
                    $subscription.BaseObject.Subscription.Delivery.Batching.MaxItems = $MaxItems.ToString() 
                }
                "TransportName" {
                    $propertyNameChangeList += "TransportName"
                    $subscription.BaseObject.Subscription.TransportName = $TransportName 
                }
                "SourceDomainComputer" {
                    $propertyNameChangeList += "SourceDomainComputer"

                    # not support yet
                    Write-PSFMessage -Level Warning -Message "modifying SourceDomainComputer is not support yet"
                }
                "SourceNonDomainDNSList" {
                    $propertyNameChangeList += "SourceNonDomainDNSList"

                    # not support yet
                    Write-PSFMessage -Level Warning -Message "modifying SourceNonDomainDNSList is not support yet"
                }
                "SourceNonDomainIssuerCAThumbprint" {
                    $propertyNameChangeList += "SourceNonDomainIssuerCAThumbprint"

                    # not support yet
                    Write-PSFMessage -Level Warning -Message "modifying SourceNonDomainIssuerCAThumbprint is not support yet"
                }
                "Expires" {
                    $propertyNameChangeList += "Expires"

                    
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
                    ComputerName = $subscription.ComputerName
                    ErrorAction = "Stop"
                    ArgumentList = @($subscriptionNameOld, $subscription.BaseObject.InnerXml, "WEF.$( [system.guid]::newguid().guid ).xml")
                }
                if($Credential) { $invokeParams.Add("Credential", $Credential)}
                
                # Create temp file name 
                Invoke-PSFCommand @invokeParams -ScriptBlock { Set-Content -Path "$env:TEMP\$( $args[2] )" -Value $args[1] -Force -ErrorAction Stop } #tempFileName , xmlcontent 
                
                # Delete existing subscription. Has to run with start-process to gather error-channel
                $result = Invoke-PSFCommand @invokeParams -ErrorVariable ExecError -ScriptBlock { 
                    Start-Process -FilePath "$env:windir\system32\wecutil.exe" -ArgumentList "delete-subscription $($args[0])" -Wait -NoNewWindow -RedirectStandardError $env:TEMP\$( $args[2] ).delete_error  #subscriptionName
                    Get-Content -Path "$env:TEMP\$( $args[2] ).delete_error"
                    Remove-Item -Path "$env:TEMP\$( $args[2] ).delete_error" -Force -Confirm:$false  #Erro redirect file 
                }
                if($result) {
                    # This one should not happen - this will be an unexpected behaviour
                    throw "Error deleting existing subscription! $($result)"
                }

                # Recreate changed subscription
                $result = Invoke-PSFCommand @invokeParams -ErrorVariable ExecError -ScriptBlock { 
                    Start-Process -FilePath "$env:windir\system32\wecutil.exe" -ArgumentList "create-subscription $env:TEMP\$( $args[2] )" -Wait -NoNewWindow -RedirectStandardError $env:TEMP\$( $args[2] ).create_error  #tempFileName
                    Get-Content -Path "$env:TEMP\$( $args[2] ).create_error"
                    Remove-Item -Path "$env:TEMP\$( $args[2] ).create_error" -Force -Confirm:$false  #Erro redirect file 
                }

                # Cleanup the xml garbage (temp file)
                # Invoke-PSFCommand @invokeParams -ScriptBlock { Remove-Item -Path "$env:TEMP\$( $args[2] )" -Force -Confirm:$false } #tempFileName  
                if(-not $result) {
                    Write-PSFMessage -Level Host -Message " OK, delete temp stuff" -Target $subscription.ComputerName
                    Invoke-PSFCommand @invokeParams -ScriptBlock { Remove-Item -Path "$env:TEMP\$( $args[2] )" -Force -Confirm:$false } #tempFileName  
                } else { 
                    throw "Error creating changed subscription! $($result)"
                }
            }
        }
    }

    End {
        # Clearing up the mess of variables
        Remove-Variable -Name TypeName -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}