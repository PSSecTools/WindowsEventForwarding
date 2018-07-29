function Get-WEFSubscription {
    <#
        .Synopsis
            Get-WEFSubscription

        .DESCRIPTION
            Query Windows Eventlog Forwarding subscriptions.

        .PARAMETER ComputerName
            The computer(s) to connect to.
            Supports PSSession objects, will reuse sessions.

        .PARAMETER Name
            Name of the subscription to filter by.

        .PARAMETER Type
            Filter option for only return objects by specified type

        .PARAMETER Enabled
            Filter by whether a subscription is enabled.

        .PARAMETER ReadExistingEvents
            Filter option for only return objects by state of ReadExistingEvents

        .PARAMETER ContentFormat
            Filter option for only return objects by specified content format

        .PARAMETER Credential
            The credentials to use on remote calls.

        .EXAMPLE
            PS C:\> Get-WEFSubscription

            Display all available subscription

        .EXAMPLE
            PS C:\> Get-WEFSubscription -Name MySubscription, Subscription2

            Display Subscriptions by name. Multiple values are supported

        .EXAMPLE
            PS C:\> Get-WEFSubscription -Enabled $true

            Display only subscriptions with status "enabled".
            This can filter down the output.

        .EXAMPLE
            PS C:\> Get-WEFSubscription -ContentFormat RenderedText

            Display only subscriptions with contentformat "RenderedText" set.
            This can filter down the output.

        .EXAMPLE
            PS C:\> "MySubscription" | Get-WEFSubscription -ComputerName Server01

            Display the subscription "MySubscription" from the remote server "Server01".
            Arrays can be piped in or specified as ComputerName ether.

        .EXAMPLE
            PS C:\> "Server01" | Get-WEFSubscription -Name "MySubscription"

            Display the subscription "MySubscription" from the remote server "Server01".
            Arrays can be piped in or specified as ComputerName ether.
            Please notice, that this is a differnt parmeter set from the previous example.

        .EXAMPLE
            PS C:\> $Session | Get-WEFSubscription "MySubscription*"

            Display subscriptions from an existing PSRemoting session.
            The $session variable has to be declared before. (e.g. $Session = New-PSSession -ComputerName Server01)

        .NOTES
            Author: Andreas Bellstedt

        .LINK
            https://github.com/AndiBellstedt/WindowsEventForwarding
    #>
    [CmdletBinding(DefaultParameterSetName = 'ComputerName',
        ConfirmImpact = 'low')]
    Param(
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        [Alias("DisplayName", "SubscriptionID", "Idendity")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name,

        [Parameter(ParameterSetName = "ComputerName", ValueFromPipeline = $true, Position = 1)]
        [Alias("host", "hostname", "Computer", "DNSHostName")]
        [PSFComputer[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = "Session")]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [ValidateSet("SourceInitiated", "CollectorInitiated")]
        [string]
        $Type,

        [ValidateSet("True", "False")]
        [String]
        $Enabled,

        [ValidateSet("True", "False")]
        [string]
        $ReadExistingEvents,

        [ValidateSet("Events", "RenderedText")]
        [string]
        $ContentFormat,

        [PSCredential]
        $Credential
    )

    Begin {
        $typeName = "$($script:BaseType).Subscription"
        $listAll = $false

        # If session parameter is used -> transfer it to ComputerName,
        # The class "PSFComputer" from PSFramework can handle it. This simplifies the handling in the further process block
        if ($Session) { $ComputerName = $Session }

        if ($Enabled) { [bool]$filterEnabled = [bool]::Parse($Enabled) }
        if ($ReadExistingEvents) { [bool]$filterExistingEvents = [bool]::Parse($ReadExistingEvents) }
        $nameBound = Test-PSFParameterBinding -ParameterName Name
        $computerBound = Test-PSFParameterBinding -ParameterName ComputerName
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
            #region Connecting and gathering prerequisites
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
                Stop-PSFFunction -Message "Working with eventlog subscriptions requires  the 'Windows Event Collector' service in running state.  Please ensure that the service is set up correctly or use 'wecutil.exe qc'."
                return
            }

            # Get a list of names for all subscriptions available on the system
            Write-PSFMessage -Level Debug -Message "Enumerating subscriptions on $($computer)" -Target $computer
            $subscriptionEnumeration = Invoke-PSFCommand @paramInvokeCmd -ScriptBlock { . "$env:windir\system32\wecutil.exe" "enum-subscription" }
            Write-PSFMessage -Level Verbose -Message "Found $($subscriptionEnumeration.count) subscription(s) on $($computer)" -Target $computer

            # If parameter name is not specified - query all available subscrptions
            if (-not $Name) {
                $listAll = $true
                Write-PSFMessage -Level Debug -Message "No name specified. Query all available subscriptions"
                [array]$Name = $subscriptionEnumeration
            }
            #endregion Connecting and gathering prerequisites

            #region Processing Events
            foreach ($nameItem in $Name) {
                # Filtering out the subscriptions to query
                $subscriptionItemsToQuery = $subscriptionEnumeration | Where-Object { $_ -like $nameItem }

                # Query subscription infos if there is a matching subscription in the list
                if ($subscriptionItemsToQuery) {
                    $subscriptions = @()
                    [array]$subscriptions = foreach ($subscriptionItemToQuery in $subscriptionItemsToQuery) {
                        Write-PSFMessage -Level Verbose -Message "Query subscription '$($subscriptionItemToQuery)' on $($computer)" -Target $computer
                        [xml]$result = Invoke-PSFCommand @paramInvokeCmd -ScriptBlock { . "$env:windir\system32\wecutil.exe" "get-subscription" $args[0] "/format:xml" } -ArgumentList $subscriptionItemToQuery

                        # Apply filter - if specified in parameters
                        if ($Type -and ($Type -ne $result.Subscription.SubscriptionType)) { continue }
                        if ($Enabled -and ($filterEnabled -ne [bool]::Parse($result.Subscription.Enabled))) { continue }
                        if ($ReadExistingEvents -and ($filterExistingEvents -ne [bool]::Parse($result.Subscription.ReadExistingEvents))) { continue }
                        if ($ContentFormat -and ($ContentFormat -ne $result.Subscription.ContentFormat)) { continue }

                        $result

                        # Clean up the mess
                        Clear-Variable -Name result -Force -Confirm:$false -Verbose:$false -WhatIf:$false -Debug:$false
                    }
                }

                # Transforming xml infos to powershell objects
                if (-not $subscriptions -and -not $listAll) {
                    Write-PSFMessage -Level Warning -Message "Subscription '$($nameItem)' not found on $($computer) or filtered out." -Target $computer
                    continue
                }
                foreach ($subscription in $subscriptions) {
                    Write-PSFMessage -Level Debug -Message "Processing subscription $($subscription.Subscription.SubscriptionId)" -Target $computer

                    # Compiling the output object
                    $subscriptionObjectProperties = [ordered]@{
                        BaseObject = $subscription
                    }
                    $output = New-Object -TypeName "$($typeName)$($subscription.Subscription.SubscriptionType)" -Property $subscriptionObjectProperties
                    if(-not $Computer.IsLocalHost) { Add-Member -InputObject $output -MemberType NoteProperty -Name "PSComputerName" -Value $Computer.ComputerName -Force }

                    # write the object to the pipeline
                    $output
                }
            }
            #endregion Processing Events

            Remove-Variable -Name paramInvokeCmd -Force -Confirm:$false -Verbose:$false -WhatIf:$false -Debug:$false
        }
    }

    End {
    }
}
