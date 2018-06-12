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
		
		Display one or more subscription from one or more remote server.
	
	.EXAMPLE
		PS C:\> $Session | Get-WEFSubscription "MySubscription*"
		
		Display subscriptions from an existing PSRemoting session.
		The $session variable has to be declared before. (e.g. $Session = New-PSSession -ComputerName Server01)
	
	.NOTES
		Author: Andreas Bellstedt
	
	.LINK
		https://github.com/AndiBellstedt/WindowsEventForwarding
#>
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    Param (
        [Parameter(ValueFromPipeline = $true, ParameterSetName = "Name")]
        [Alias("host", "hostname", "Computer", "DNSHostName")]
        [PSFComputer[]]
        $ComputerName = $env:COMPUTERNAME,
		
        [Parameter(ParameterSetName = "Session")]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,
		
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        [Alias("DisplayName", "SubscriptionID")]
        [String[]]
        $Name,
		
        [ValidateSet("SourceInitiated", "CollectorInitiated")]
        [string]
        $Type,
		
        [ValidateSet($true, $false)]
        [String]
        $Enabled,
		
        [ValidateSet($true, $false)]
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
        if ($Enabled) { [bool]$filterEnabled = [bool]::Parse($Enabled) }
        if ($ReadExistingEvents) { [bool]$filterExistingEvents = [bool]::Parse($ReadExistingEvents) }
        $listAll = $false
		
        if ($Session) { $ComputerName = $Session }
    }
	
    Process {
		# Workarroud parameter "Name", when Computername was piped into the function
		#? ($PsCmdlet.ParameterSetName -eq "Name")
		if ($Name -eq $ComputerName.ComputerName) { $Name = "" }
		
        foreach ($computer in $ComputerName) {
            #region Connecting and gathering prerequisites
            Write-PSFMessage -Level VeryVerbose -Message "Processing $computer" -Target $computer
			
            # Check service 'Windows Event Collector' - without this, there are not subscriptions possible
            Write-PSFMessage -Level Verbose -Message "Checking service 'Windows Event Collector'" -Target $computer
            $service = Invoke-PSFCommand -ComputerName $computer -ScriptBlock { Get-Service -Name "wecsvc" } -ErrorAction Stop
			
            if ($service.Status -ne 'Running') {
                throw "Working with eventlog subscriptions requires  the 'Windows Event Collector' service in running state.  Please ensure that the service is set up correctly or use 'wecutil.exe qc'."
            }
			
            # Get a list of names for all subscriptions available on the system
            Write-PSFMessage -Level Debug -Message "Enumerating subscriptions on $($computer)" -Target $computer
            $subscriptionEnumeration = Invoke-PSFCommand -ComputerName $computer -ScriptBlock { . "$env:windir\system32\wecutil.exe" "enum-subscription" } -ErrorAction Stop
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
                        [xml]$result = Invoke-PSFCommand -ComputerName $computer -ScriptBlock { . "$env:windir\system32\wecutil.exe" "get-subscription" $args[0] "/format:xml" } -ErrorAction Stop -ArgumentList $subscriptionItemToQuery
						
                        # Apply filter - if specified in parameters
                        if ($Type -and ($Type -ne $result.Subscription.SubscriptionType)) { continue }
                        if ($Enabled -and ($filterEnabled -ne [bool]::Parse($result.Subscription.Enabled))) { continue }
                        if ($ReadExistingEvents -and ($filterExistingEvents -ne [bool]::Parse($result.Subscription.ReadExistingEvents))) { continue }
                        if ($ContentFormat -and ($ContentFormat -ne $result.Subscription.ContentFormat)) { continue }
									
                        $result
						
                        # Clean up the mess
                        Clear-Variable -Name result -Force -Confirm:$false -Verbose:$false
                    }
                }
				
                # Transforming xml infos to powershell objects
                if (-not $subscriptions -and -not $listAll) {
                    Write-PSFMessage -Level Verbose -Message "Subscription '$($nameItem)' not found on $($computer) or filtered out." -Target $computer
                    continue
                }
                foreach ($subscription in $subscriptions) {
                    Write-PSFMessage -Level Debug -Message "Processing subscription $($subscription.Subscription.SubscriptionId)" -Target $computer
					
                    # Compiling the output object
                    $subscriptionObjectProperties = [ordered]@{
                        BaseObject = $subscription
                        PSSession  = $Session
                    }
                    $output = New-Object -TypeName psobject -Property $subscriptionObjectProperties
					
                    # Add typnames to the output object. this adds all the script properties to the output object,
                    $output.pstypenames.Insert(0, $BaseType)
                    $output.pstypenames.Insert(0, $typeName)
                    $output.pstypenames.Insert(0, "$($typeName).$($subscription.Subscription.SubscriptionType)")
					
                    # write the object to the pipeline
                    $output
                }
            }
            #endregion Processing Events
        }
    }
	
    End {
		
    }
}