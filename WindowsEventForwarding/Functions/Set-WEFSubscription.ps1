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
        ConfirmImpact = 'medium')]
    Param(
        [Parameter(ValueFromPipeline = $true, Position = 0, ParameterSetName = "InputObject", Mandatory=$true)]
        [WEF.Subscription]
        $InputObject,

        [Parameter(ValueFromPipeline = $true, Position = 0, ParameterSetName = "Name", Mandatory=$true)]
        [Parameter(ValueFromPipeline = $false, Position = 0, ParameterSetName = "ComputerName", Mandatory=$true)]
        [Parameter(ValueFromPipeline = $false, Position = 0, ParameterSetName = "Session", Mandatory=$true)]
        [Alias("DisplayName", "SubscriptionID", "Idendity")]
        [String]
        $Name,

        [Parameter(ValueFromPipeline = $true, Position = 1, ParameterSetName = "ComputerName")]
        [Alias("host", "hostname", "Computer", "DNSHostName")]
        [PSFComputer[]]
        $ComputerName = $env:COMPUTERNAME,
		
        [Parameter(ValueFromPipeline = $true, ParameterSetName = "Session")]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [String]
        $NewName,

        
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
    }

    Process {
        Write-PSFMessage -Level Debug -Message "ParameterNameSet: $($PsCmdlet.ParameterSetName)"

        # When Session parameter is used, or a session object is piped in, transfer it to ComputerName,
        # because of the class "PSFComputer" from PSFramework can handle it. This simplifies the handling
        # in the further process block 
        if($PsCmdlet.ParameterSetName -eq "Session") { $ComputerName = $Session }
        
        # Checking Parameterset - when not inputobject query for existiing object to modiy 
        if($PsCmdlet.ParameterSetName -ne "InputObject") {
            $getParms = @{
                Name = $Name
            }
            # Conitinue HERE
            $InputObject = Get-WEFSubscriptiont @getParms
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