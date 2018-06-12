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
    [CmdletBinding( DefaultParameterSetName = 'Name',
        SupportsShouldProcess = $true,
        PositionalBinding = $true,
        ConfirmImpact = 'medium')]
    Param(
        [Parameter(ParameterSetName = "InputObject",
            Mandatory=$true,
            ValueFromPipeline = $true)]
        [WEF.Subscription]
        $InputObject,

        [Parameter(ParameterSetName = "Name",
            ValueFromPipeline = $true)]
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
        
        [String]
        $Enabled,

        [bool]
        $ReadExistingEvents,

        [ValidateSet("Events", "RenderedText")]
        [string]
        $ContentFormat,

        [PSCredential]
        $Credential
    )

    Begin {
        $Local:TypeName = "$($BaseType).Subscription"
        if ($Session) { $ComputerName = $Session }
    }

    Process {
        Write-PSFMessage -Level Verbose -Message "Parameterset: $($PsCmdlet.ParameterSetName)"
        if($PsCmdlet.ParameterSetName -like "InputObject") {
            # ???? -> continue
        }

        foreach ($ComputerNameItem in $ComputerName) {
            #region Connecting and gathering prerequisites
            Write-PSFMessage -Level VeryVerbose -Message "Processing $computer" -Target $computer

            # Check service 'Windows Event Collector' - without this, there are not subscriptions possible
            Write-PSFMessage -Level Verbose -Message "Checking service 'Windows Event Collector'" -Target $computer
            $service = Invoke-PSFCommand -ComputerName $computer -ScriptBlock { Get-Service -Name "wecsvc" } -ErrorAction Stop
            
            if ($service.Status -ne 'Running') {
                throw "Working with eventlog subscriptions requires  the 'Windows Event Collector' service in running state.  Please ensure that the service is set up correctly or use 'wecutil.exe qc'."
            }
            
            
        }
    }

    End {
        # Clearing up the mess of variables
        Remove-Variable -Name TypeName -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}