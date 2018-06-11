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
    [CmdletBinding( DefaultParameterSetName = 'DefaultParameterSet',
        SupportsShouldProcess = $true,
        PositionalBinding = $true,
        ConfirmImpact = 'medium')]
    Param(
        # Remote computer name. (PSRemoting required)
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithComputerName',
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false)]
        [Alias("host", "hostname", "Computer", "DNSHostName")]
        [String[]]$ComputerName = $env:COMPUTERNAME,

        # For usage with existing PSRemoting session
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithSession',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $false)]
        [Alias()]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        # The name of the subscription
        [Parameter(Mandatory = $false,
            ParameterSetName = 'DefaultParameterSet',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithComputerName',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $false,
            Position = 0)]
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RemotingWithSession',
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 0)]
        [Alias("DisplayName", "SubscriptionID")]
        [String[]]$Name,
        
        # Set the state of a subscription
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false)]
        [bool]$Enabled,

        # Specifies that existing events before the subscription was applied are also transfered to the WEF server  
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false)]
        [bool]$ReadExistingEvents,

        # Set content format for a subscription
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false)]
        [ValidateSet("Events", "RenderedText")] 
        [string]$ContentFormat,

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
        Write-Verbose "Parameterset: $($PsCmdlet.ParameterSetName)"
        foreach ($ComputerNameItem in $ComputerName) {
            # creating session when remoting is used and a session isn't already available
            if ( $PsCmdlet.ParameterSetName -eq "RemotingWithComputerName" ) {
                Write-Verbose "Use $($PsCmdlet.ParameterSetName). Creating session to '$($ComputerNameItem)'"
                $Local:Parameter = @{
                    ComputerName  = $ComputerNameItem
                    Name          = "WEFSession"
                    ErrorAction   = "Stop"
                    ErrorVariable = "SessionError"
                }
                if ($Credential) { $Parameter.Add("Credential", $Credential) }
                try {
                    $Session = New-PSSession @Parameter
                }
                catch {
                    $SessionError | Write-Error 
                    continue
                }
                Write-Debug "Session '$($Session.Name)' to $($Session.ComputerName) created."
                Remove-Variable -Name Parameter -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }

        }
    }

    End {
        # Clearing up the mess of variables
        Remove-Variable -Name TypeName -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}