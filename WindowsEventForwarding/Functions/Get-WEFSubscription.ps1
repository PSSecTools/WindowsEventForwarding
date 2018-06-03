function Get-WEFSubscription {
    <#
        .Synopsis
        Get-WEFSubscription

        .DESCRIPTION
        Query Windows Eventlog Forwarding subscriptions.

        .NOTES
        Author: Andreas Bellstedt

        .LINK
        https://github.com/AndiBellstedt/WindowsEventForwarding

        .EXAMPLE
        Get-WEFSubscription
        Display all available subscription 

        .EXAMPLE
        Get-WEFSubscription -Name MySubscription, Subscription2
        Display subscriptions by name. Multiple values are supported

        .EXAMPLE
        "MySubscription" | Get-WEFSubscription -ComputerName Server01 
        Display one or more subscription from one or more remote server.

        .EXAMPLE
        $Session | Get-WEFSubscription "MySubscription*" 
        Display subscriptions from an existing PSRemoting session.
        The $session variable has to be declared before. (e.g. $Session = New-PSSession -ComputerName Server01)

    #>
    [CmdletBinding( DefaultParameterSetName = 'DefaultParameterSet',
        SupportsShouldProcess = $false,
        PositionalBinding = $true,
        ConfirmImpact = 'Low')]
    Param(
        # The name of the subscription
        [Parameter(Mandatory = $false,
            ParameterSetName = 'DefaultParameterSet',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithComputerName',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithSession',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Alias("DisplayName", "SubscriptionID")]
        [String[]]$Name,

        # Remote computer name. (PSRemoting required)
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithComputerName',
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Alias("host", "hostname", "Computer", "DNSHostName")]
        [String[]]$ComputerName,

        # For usage with existing PSRemoting session
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithSession',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Alias()]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        # Credentials for remote computer (PSRemoting required)
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithComputerName',
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Alias()]
        [pscredential]$Credential
    )

    Begin {
        $Local:TypeName = "$($BaseType).Subscription"
    }

    Process {
        # work arround for wrong parameter pipeline parsing. Don't know why this occours.
        if ($PsCmdlet.ParameterSetName -eq "RemotingWithSession") { if ($Name -eq $Session.Name) { $Name = "" } }

        # creating session when remoting is used and a session isn't already available
        if ( $PsCmdlet.ParameterSetName -eq "RemotingWithComputerName" ) {
            Write-Verbose "Use $($PsCmdlet.ParameterSetName). Creating session to '$($ComputerName)'"
            $Local:Parameter = @{
                ComputerName = $ComputerName
                Name         = "WEFSession"
            }
            if ($Credential) { $Parameter.Add("Credential", $Credential) }
            $Session = New-PSSession @Parameter
            Write-Debug "Session '$($Session.Name)' to $($Session.ComputerName) created."
            Remove-Variable -Name Parameter -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }

        # Check service 'Windows Event Collector' - without this, there are not subscriptions possible
        Write-Debug "Check service 'Windows Event Collector'"
        if ($Session) {
            $Service = Invoke-Command -Session $Session -ScriptBlock { Get-Service -Name "wecsvc" } -ErrorAction Stop
        } else {
            $Service = Get-Service -Name "wecsvc" -ErrorAction Stop
        }
        if ($Service.Status -ne 'Running') {
            throw "Working with eventlog subscriptions requires  the 'Windows Event Collector' service in running state.  Please ensure that the service is set up correctly or use 'wecutil.exe qc'."
        }
        
        # Get a list of names for all subscriptions available on the system
        if ($Session) {
            Write-Debug "Enumerating subscriptions on $($Session.ComputerName)"
            $SubscriptionEnumeration = Invoke-Command -Session $Session -ScriptBlock { . "$env:windir\system32\wecutil.exe" "enum-subscription" } -ErrorAction Stop
            Write-Verbose "Found $($SubscriptionEnumeration.count) subscription(s) on $($Session.ComputerName)"
        } else {
            Write-debug "Enumerating subscriptions on local sytem"
            $SubscriptionEnumeration = . "$env:windir\system32\wecutil.exe" "enum-subscription"
            Write-Verbose "Found $($SubscriptionEnumeration.count) subscription(s) on local sytem"
        }

        # if parameter name is not specified - 
        if (-not $Name) { 
            Write-Verbose "No name specified. Query all available subscriptions"
            [array]$Name = $SubscriptionEnumeration 
        }

        # Looping through every name from parameter, or every subscription found in the system (if parameter was not specified)
        foreach ($NameItem in $Name) { 
            if($SubscriptionEnumeration.count -gt 1) {
                $SubscriptionItemsToQuery = $SubscriptionEnumeration -like $NameItem
            } else {
                if($SubscriptionEnumeration -like $NameItem) {
                    [array]$SubscriptionItemsToQuery = $SubscriptionEnumeration
                }
            }
            if ($SubscriptionItemsToQuery) {
                $Subscriptions = @()
                foreach ($SubscriptionItemToQuery in $SubscriptionItemsToQuery) {
                    if ($Session) {
                        Write-Verbose "Query subscription '$($SubscriptionItemToQuery)' on $($Session.ComputerName)"
                        [xml]$result = Invoke-Command -Session $Session -ScriptBlock { . "$env:windir\system32\wecutil.exe" "get-subscription" $using:SubscriptionItemToQuery "/format:xml" } -ErrorAction Stop
                    } else {
                        Write-Verbose "Query subscription '$($SubscriptionItemToQuery)' on local system"
                        [xml]$result = . "$env:windir\system32\wecutil.exe" "get-subscription" $SubscriptionItemToQuery "/format:xml"
                    }
                    $Subscriptions += $result
                    Clear-Variable -Name result -Force -Confirm:$false -Verbose:$false
                }
                
            }
            
            # Transforming xml infos to powershell objects
            if (-not $Subscriptions) {
                Write-Warning "No subscription '$($NameItem)' found on $(if($Session) { $Session.ComputerName } else { "local system"} )"
            } else {
                foreach ($Subscription in $Subscriptions) { 
                    Write-Debug "Working on subscription $($Subscription.Subscription.SubscriptionId)"
                    
                    # The list of non domain targets for subscription
                    if ( $Subscription.Subscription.AllowedSourceNonDomainComputers.AllowedSubjectList -or $Subscription.Subscription.AllowedSourceNonDomainComputers.AllowedIssuerCAList -or $Subscription.Subscription.AllowedSourceNonDomainComputers.DeniedSubjectList ) { 
                        $AllowedSourceNonDomainComputers = New-Object -TypeName psobject -Property ([ordered]@{
                                AllowedSubjectList  = [String]::Join(', ', $Subscription.Subscription.AllowedSourceNonDomainComputers.AllowedSubjectList.Subject)
                                AllowedIssuerCAList = [String]::Join(', ', $Subscription.Subscription.AllowedSourceNonDomainComputers.AllowedIssuerCAList.IssuerCA)
                                DeniedSubjectList   = [String]::Join(', ', $Subscription.Subscription.AllowedSourceNonDomainComputers.DeniedSubjectList.Subject)
                            })
                    } else { 
                        [System.String]$AllowedSourceNonDomainComputers = ""
                    }

                    # The list of domain targets for subscription
                    if ( $Subscription.Subscription.AllowedSourceDomainComputers ) { 
                        $SDDLObject = $Subscription.Subscription.AllowedSourceDomainComputers | ConvertFrom-SddlString
                        $AllowedSourceDomainComputers = $SDDLObject.DiscretionaryAcl | ForEach-Object { $_.split(':')[0] }
                    } else { 
                        [System.String]$AllowedSourceDomainComputers = "" 
                    }

                    # Compiling the output object
                    $SubscriptionObjectProperties = [ordered]@{
                        BaseObject                             = $Subscription
                        PSSession                              = $Session
                        SubscriptionID                         = [System.String]$Subscription.Subscription.SubscriptionId
                        SubscriptionType                       = [System.String]$Subscription.Subscription.SubscriptionType
                        Description                            = [System.String]$Subscription.Subscription.Description
                        Enabled                                = [bool]::Parse($Subscription.Subscription.Enabled)
                        DeliveryMode                           = [System.String]$Subscription.Subscription.Delivery.Mode
                        MaxItems                               = [System.Int32]$Subscription.Subscription.Delivery.Batching.MaxItems
                        MaxLatencyTime                         = [System.UInt64]$Subscription.Subscription.Delivery.Batching.MaxLatencyTime
                        HeartBeatIntervalTime                  = [System.UInt64]$Subscription.Subscription.Delivery.PushSettings.Heartbeat.Interval
                        ReadExistingEvents                     = [bool]::Parse($Subscription.Subscription.ReadExistingEvents)
                        TransportName                          = [System.String]$Subscription.Subscription.TransportName
                        ContentFormat                          = [System.String]$Subscription.Subscription.ContentFormat
                        Locale                                 = [System.String]$Subscription.Subscription.Locale.Language
                        LogFile                                = [System.String]$Subscription.Subscription.LogFile
                        CredentialsType                        = [System.String]$Subscription.Subscription.CredentialsType
                        AllowedSourceNonDomainComputers        = $AllowedSourceNonDomainComputers
                        AllowedSourceDomainComputers           = $AllowedSourceDomainComputers
                        Query                                  = [String]::Join("`n", ($Subscription.Subscription.Query.'#cdata-section').Trim() )
                        PublisherName                          = [System.String]$Subscription.Subscription.PublisherName
                        AllowedSourceDomainComputersSDDLString = $Subscription.Subscription.AllowedSourceDomainComputers
                        AllowedSourceDomainComputersSDDLObject = $SDDLObject
                        #PSComputerName                         = if($Session) { $Session.ComputerName.ToUpper() }
                    }
                    $Output = New-Object -TypeName psobject -Property $SubscriptionObjectProperties
                    $Output.pstypenames.Insert(0, $BaseType)
                    $Output.pstypenames.Insert(0, $TypeName)
                    $Output.pstypenames.Insert(0, "$($TypeName).$($Subscription.Subscription.SubscriptionType)")
                    Write-Output -InputObject $Output

                    # Clearing up the mess of variables
                    Remove-Variable -Name AllowedSourceNonDomainComputers, AllowedSourceDomainComputers, SDDLObject -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                }
            }
        }

        if ( $PsCmdlet.ParameterSetName -eq "RemotingWithComputerName" ) {
            $Session | Remove-PSSession -Confirm:$false 
        }
    }

    End {
    }
}