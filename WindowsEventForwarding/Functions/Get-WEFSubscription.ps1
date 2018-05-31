function Get-WEFSubscription {
    <#
        .Synopsis
        Get-WEFSubscription

        .DESCRIPTION
        Query Windows Eventlog Forwarding subscriptions.

        .NOTES
        Author: Andreas Bellstedt

        .LINK
        https://github.com/AndiBellstedt/

        .EXAMPLE
        Get-WEFSubscription
        Display all available subscription 

        .EXAMPLE
        Get-WEFSubscription -Name MySubscription
        Display only a specific subscription 

        .EXAMPLE
        Get-WEFSubscription MySubscription1, Subscription2
        Display multiple subscription.

        #>
    [CmdletBinding(DefaultParameterSetName = 'DefaultParameterSet',
        SupportsShouldProcess = $false,
        PositionalBinding = $true,
        ConfirmImpact = 'Low')]
    Param(
        # The name of the subscription
        [Parameter(Mandatory = $false,
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
        [Alias("host", "hostname", "Computer")]
        [String]$ComputerName,

        # Credentials for remote computer (PSRemoting required)
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithComputerName',
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Alias()]
        [pscredential]$Credential,

        # Existing PSRemoting session
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithSession',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias("PSSession")]
        [System.Management.Automation.Runspaces.PSSession]$Session

    )

    Begin {
        if($PsCmdlet.ParameterSetName -eq "RemotingWithComputerName") {
            $Local:Parameter = @{
                ComputerName = $ComputerName
                Name = "WEFSession"
            }
            if($Credential) { $Parameter.Add("Credential", $Credential) }
            $Session = New-PSSession @Parameter
            Remove-Variable -Name Parameter -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }

        Write-Debug "Check service 'Windows Event Collector'"
        if($Session) {
            $Service = Invoke-Command -Session $Session -ScriptBlock { Get-Service -Name "wecsvc" } -ErrorAction Stop
        } else {
            $Service = Get-Service -Name "wecsvc" -ErrorAction Stop
        }
        if ($Service.Status -ne 'Running') {
            throw "Working with eventlog subscriptions requires  the 'Windows Event Collector' service in running state.  Please ensure that the service is set up correctly or use 'wecutil.exe qc'."
        }
        if($Session) {
            $SubscriptionEnumeration = Invoke-Command -Session $Session -ScriptBlock { . "$env:windir\system32\wecutil.exe" "enum-subscription" } -ErrorAction Stop
        } else {
            $SubscriptionEnumeration = . "$env:windir\system32\wecutil.exe" "enum-subscription"
        }
    }

    Process {
        if (-not $Name) {
            Write-Debug "No subscription specified. Query all subscriptions."
            if($Session) {
                [array]$Name = Invoke-Command -Session $Session -ScriptBlock { . "$env:windir\system32\wecutil.exe" "enum-subscription" } -ErrorAction Stop
            } else {
                [array]$Name = . "$env:windir\system32\wecutil.exe" "enum-subscription"
            }
        }
        
        foreach ($NameItem in $Name) { 
            $SubscriptionItemsToQuery = $SubscriptionEnumeration -like $NameItem
            if ($SubscriptionItemsToQuery) {
                $Subcriptions = @()
                #$SubscriptionItemToQuery = "NonDomainComputer"
                foreach ($SubscriptionItemToQuery in $SubscriptionItemsToQuery) {
                    if($Session) {
                        [xml]$result = Invoke-Command -Session $Session -ScriptBlock { . "$env:windir\system32\wecutil.exe" "get-subscription" $using:SubscriptionItemToQuery "/format:xml" } -ErrorAction Stop
                    } else {
                        [xml]$result = . "$env:windir\system32\wecutil.exe" "get-subscription" $SubscriptionItemToQuery "/format:xml"
                    }
                    $Subcriptions += $result
                    Clear-Variable -Name result -Force -Confirm:$false -Verbose:$false
                }
                
            }

            if($Subcriptions) {
                foreach ($Subcription in $Subcriptions) { 
                    if ( $Subcription.Subscription.AllowedSourceNonDomainComputers.AllowedSubjectList -or $Subcription.Subscription.AllowedSourceNonDomainComputers.AllowedIssuerCAList -or $Subcription.Subscription.AllowedSourceNonDomainComputers.DeniedSubjectList ) { 
                        $AllowedSourceNonDomainComputers = New-Object -TypeName psobject -Property ([ordered]@{
                            AllowedSubjectList  = [String]::Join(', ',$Subcription.Subscription.AllowedSourceNonDomainComputers.AllowedSubjectList.Subject)
                            AllowedIssuerCAList = [String]::Join(', ',$Subcription.Subscription.AllowedSourceNonDomainComputers.AllowedIssuerCAList.IssuerCA)
                            DeniedSubjectList   = [String]::Join(', ',$Subcription.Subscription.AllowedSourceNonDomainComputers.DeniedSubjectList.Subject)
                        })
                    } else { 
                        [System.String]$AllowedSourceNonDomainComputers = ""
                    }

                    if ( $Subcription.Subscription.AllowedSourceDomainComputers ) { 
                        $SDDLObject = $Subcription.Subscription.AllowedSourceDomainComputers | ConvertFrom-SddlString
                        $AllowedSourceDomainComputers = $SDDLObject.DiscretionaryAcl | ForEach-Object { $_.split(':')[0] }
                    } else { 
                        [System.String]$AllowedSourceDomainComputers = "" 
                    }

                    if ( ($Subcription.Subscription.Query.'#cdata-section').count -gt 1) {
                        [System.String[]]$Query = ($Subcription.Subscription.Query.'#cdata-section').Trim()
                    } else { 
                        [System.String]$Query = ($Subcription.Subscription.Query.'#cdata-section').Trim()
                    }

                    $SubscriptionObjectProperties = [ordered]@{
                        SubscriptionID                         = [System.String]$Subcription.Subscription.SubscriptionId
                        SubscriptionType                       = [System.String]$Subcription.Subscription.SubscriptionType
                        Description                            = [System.String]$Subcription.Subscription.Description
                        Enabled                                = [System.String]$Subcription.Subscription.Enabled
                        DeliveryMode                           = [System.String]$Subcription.Subscription.Delivery.Mode
                        MaxItems                               = [System.Int32]$Subcription.Subscription.Delivery.Batching.MaxItems
                        MaxLatencyTime                         = [System.UInt64]$Subcription.Subscription.Delivery.Batching.MaxLatencyTime
                        HeartBeatInterval                      = [System.UInt64]$Subcription.Subscription.Delivery.PushSettings.Heartbeat.Interval
                        ReadExistingEvents                     = [System.String]$Subcription.Subscription.ReadExistingEvents
                        TransportName                          = [System.String]$Subcription.Subscription.TransportName
                        ContentFormat                          = [System.String]$Subcription.Subscription.ContentFormat
                        Locale                                 = [System.String]$Subcription.Subscription.Locale.Language
                        LogFile                                = [System.String]$Subcription.Subscription.LogFile
                        CredentialsType                        = [System.String]$Subcription.Subscription.CredentialsType
                        AllowedSourceNonDomainComputers        = $AllowedSourceNonDomainComputers
                        AllowedSourceDomainComputers           = $AllowedSourceDomainComputers
                        Query                                  = $Query
                        PublisherName                          = [System.String]$Subcription.Subscription.PublisherName
                        AllowedSourceDomainComputersSDDLString = $Subcription.Subscription.AllowedSourceDomainComputers
                        AllowedSourceDomainComputersSDDLObject = $SDDLObject
                    }
                    
                    $Output = New-Object -TypeName psobject -Property $SubscriptionObjectProperties
                    $Output

                    Remove-Variable -Name AllowedSourceNonDomainComputers, AllowedSourceDomainComputers, Query, SDDLObject -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                }
            } else {
                Write-Warning "No subscription '$($NameItem)' found"
            }
        }
    }

    End {
        if($Session) {
            Remove-PSSession -Session $Session -Confirm:$false
        }
    }
}