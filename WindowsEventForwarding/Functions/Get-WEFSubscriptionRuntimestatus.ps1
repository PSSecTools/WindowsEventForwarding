function Get-WEFSubscriptionRuntimestatus {
    <#
        .Synopsis
            Get-WEFSubscriptionRuntimestatus

        .DESCRIPTION
            Query status information for a Windows Eventlog Forwarding subscription

        .PARAMETER InputObject
            Pipeline catching object for Get-WEFSubscription

        .PARAMETER ComputerName
            The computer(s) to connect to.
            Supports PSSession objects, will reuse sessions.

            Available aliases: "host", "hostname", "Computer", "DNSHostName"

        .PARAMETER Session
            PSSession(s) to connect to.

        .PARAMETER Name
            Name of the subscription to query for runtimestatus.
            Only needed when InputObject is not used.
            Must be specified when piping in a computername or a session.

            Available aliases: "DisplayName", "SubscriptionID", "Idendity"

        .PARAMETER Credential
            The credentials to use on remote calls.

        .EXAMPLE
            PS C:\> Get-WEFSubscriptionRuntimestatus -Name "Subscription1"

            Query status information for subscription "Subscription1"

        .EXAMPLE
            PS C:\> Get-WEFSubscription -Name "Subscription1" | Get-WEFSubscriptionRuntimestatus

            Query status information for subscription "Subscription1" by using the pipeline.

        .NOTES
            Author: Andreas Bellstedt

        .LINK
            https://github.com/AndiBellstedt/WindowsEventForwarding
    #>
    [CmdletBinding( DefaultParameterSetName = 'ComputerName',
        ConfirmImpact = 'low')]
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
        $Credential
    )

    Begin {
        # If session parameter is used -> transfer it to ComputerName,
        # The class "PSFComputer" from PSFramework can handle it. This simplifies the handling in the further process block
        if ($Session) { $ComputerName = $Session }
    }

    Process {
        try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
        Write-PSFMessage -Level Debug -Message "ParameterNameSet: $($PsCmdlet.ParameterSetName)"

        #region query specified subscription when not piped in
        if ($PsCmdlet.ParameterSetName -ne "InputObject") {
            # when not inputobject --> query for existing object to modify
            Write-PSFMessage -Level Verbose -Message "Gathering $ComputerName for subscription $Name"
            try {
                $InputObject = Get-WEFSubscription -Name $Name -ComputerName $ComputerName -ErrorAction Stop
            }
            catch {
                Stop-PSFFunction -Message "Error finding subscription '$name' on computer $computer" -ErrorRecord $_ -EnableException $true
            }
            if (-not $InputObject) {
                $message = "Subscription $Name not found"
                if ($ComputerName) { $message = $message + " on " + $ComputerName }
                Stop-PSFFunction -Message $message  -ErrorRecord $_ -EnableException $true
            }
        }
        #endregion query specified subscription when not piped in

        foreach ($subscription in $InputObject) {
            Write-PSFMessage -Level Verbose -Message "Processing '$($subscription.Name)' on '$($subscription.ComputerName)'" -Target $subscription.ComputerName

            #region query status information on subscription from system
            # Get-Subscriptionruntimestatus. Execute wecutil to get runtimestatus of subscription
            Write-PSFMessage -Level Verbose -Message "Get runtimestatus for subscription '$($subscription.Name)' on computer '$($subscription.ComputerName)'" -Target $subscription.ComputerName

            $invokeParams = @{
                ComputerName  = $subscription.ComputerName
                ErrorAction   = "Stop"
                ErrorVariable = "ErrorReturn"
                ArgumentList  = @(
                    $subscription.Name
                )
            }
            if ($Credential) { $invokeParams.Add("Credential", $Credential)}

            try {
                $invokeOutput = Invoke-PSFCommand @invokeParams -ScriptBlock {
                    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
                    $output = . "$env:windir\system32\wecutil.exe" "get-subscriptionruntimestatus" "$($args[0])" *>&1
                    $wecExceptions = $output | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' } *>&1
                    if ($wecExceptions) {
                        Write-Error -Message "$([string]::Join(" ", $wecExceptions.Exception.Message.Replace("`r`n"," ")))" -ErrorAction Stop
                    }
                    else {
                        $output | Where-Object pstypenames -contains 'System.String'
                    }
                }
                if ($ErrorReturn) { Write-Error "" -ErrorAction Stop}
            }
            catch {
                $ErrorReturnWEC = $ErrorReturn | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' } | select-object -Unique
                if ($ErrorReturnWEC) {
                    $ErrorMsg = [string]::Join(" ", ($ErrorReturnWEC.Exception.Message.Replace("`r`n", " ") | select-object -Unique))
                }
                else {
                    $ErrorMsg = [string]::Join(" ", ($ErrorReturn.Exception.Message | select-object -Unique))
                }

                Stop-PSFFunction -Message "Error resuming subscription '$($subscription.Name)' on computer '$($subscription.ComputerName)'! $($ErrorMsg)" -ErrorRecord $_
            }
            #endregion  query status information on subscription from system

            #region matching wecutil output and compiling output object
            if ([string]::Join("`n", $invokeOutput) -match '(Subscription: (?<SubscriptionId>.*)\n\tRunTimeStatus: (?<SubscriptionRuntimeStatus>\S*)\n\tLastError: (?<SubscriptionLastError>\S*)(\n|$))(\tEventSources:\n(?<SubscriptionEventSources>(.*\n*)*$)|(\tErrorMessage: (?<SubscriptionErrorMessage>.*)\n)\tErrorTime: (?<SubscriptionErrorTime>.*$)|$)') {
                $SubscriptionRuntimeStatus = $Matches['SubscriptionRuntimeStatus']
                $keys = $Matches.keys | Where-Object { $_ -like "Subscription*" }

                $hashTableSubscriptionStatus = [ordered]@{}
                foreach ($key in $keys) {
                    $hashTableSubscriptionStatus.Add($key, $Matches[$key])
                }

                if ($SubscriptionRuntimeStatus -eq 'Active' -or $SubscriptionRuntimeStatus -eq 'Disabled') {
                    $matchEventSources = Select-String -InputObject $hashTableSubscriptionStatus['SubscriptionEventSources'] -AllMatches -Pattern '\t{2}(?<SourceId>\S*)\n(?<SourceIdProperties>(\t{3}.*(\n|$))*)'
                    if ($matchEventSources) {
                        foreach ($eventSource in $matchEventSources.Matches) {
                            $eventSourceProperties = (Select-String -InputObject $eventSource.Groups['SourceIdProperties'].Value -AllMatches -Pattern '\t{3}(?<SourcePropertyKey>\S*): (?<SourcePropertyValue>(.*))').Matches

                            $hashTableEventSources = [ordered]@{}
                            foreach ($key in ($Keys | Where-Object {$_ -notlike "SubscriptionEventSources"})) {
                                $hashTableEventSources.Add($key, $hashTableSubscriptionStatus[$key])
                            }
                            $hashTableEventSources.Add("SourceId", $eventSource.Groups['SourceId'].Value)
                            foreach ($eventSourceProperty in $eventSourceProperties) {
                                $hashTableEventSources.Add("Source$($eventSourceProperty.Groups['SourcePropertyKey'].Value)", $eventSourceProperty.Groups['SourcePropertyValue'].Value)
                            }
                            $outputObject = [PSCustomObject]$hashTableEventSources
                        }
                    }
                    else {
                        $hashTableEventSources = [ordered]@{}
                        foreach ($key in ($Keys | Where-Object {$_ -notlike "SubscriptionEventSources"})) {
                            $hashTableEventSources.Add($key, $hashTableSubscriptionStatus[$key])
                        }
                        $outputObject = [PSCustomObject]$hashTableEventSources
                    }
                }
                else {
                    $outputObject = [PSCustomObject]$hashTableSubscriptionStatus
                }

                Add-Member -InputObject $outputObject -MemberType NoteProperty -Name "Subscription" -Value $subscription
                $outputObject.pstypenames.Insert(0, $BaseType)
                $outputObject.pstypenames.Insert(0, "$($BaseType).SubscriptionRuntimeStatus")
                $outputObject.pstypenames.Insert(0, "$($BaseType).SubscriptionRuntimeStatus.$($SubscriptionRuntimeStatus)")
                if($outputObject.SourceRunTimeStatus) {
                    $outputObject.pstypenames.Insert(0, "$($BaseType).SubscriptionRuntimeStatus.$($SubscriptionRuntimeStatus)Source$($outputObject.SourceRunTimeStatus)")
                }
                if(-not $outputObject.subscription.PSComputerName) { Add-Member -InputObject $outputObject -MemberType NoteProperty -Name "PSComputerName" -Value $outputObject.subscription.PSComputerName -Force }
                $outputObject

            }
            else {
                $message = "Warning! Can't retrieve runtimestatus for subscription '$($subscription.Name)' on computer '$($subscription.ComputerName)'"
                Write-PSFMessage -Level Warning -Message $message -Target $subscription.ComputerName -EnableException $true
            }
            #endregion matching wecutil output and compiling output object
        }
    }

    End {
    }
}
